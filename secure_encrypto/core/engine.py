"""
secure-encrypto — Core Cryptographic Engine
============================================
Algorithm : AES-256-GCM  (authenticated encryption)
KDF       : Argon2id      (memory-hard, side-channel-resistant)
Salt      : 32 bytes      (random per file)
Nonce     : 12 bytes      (random per encryption)

File format (.senc):
  [0:4]      MAGIC     — b'SENC'
  [4]        VERSION   — 0x01
  [5:18]     ARGON2    — mem(4B) + time(4B) + para(4B) + len(1B)
  [18:50]    SALT      — 32 bytes
  [50:62]    NONCE     — 12 bytes
  [62:64]    FNAME_LEN — 2 bytes big-endian
  [64:64+N]  FILENAME  — N bytes UTF-8
  [64+N:]    CIPHERTEXT + GCM AUTH TAG (16 bytes at end)

Security note on AAD:
  The GCM Additional Authenticated Data is:
      params_bytes (13 bytes) + filename (UTF-8)
  This binds the Argon2id parameters to the GCM tag, preventing any
  downgrade attack that modifies mem/time/para in the header.
"""

import os
import struct
import zipfile
import tempfile
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

from .secure_wipe import secure_delete
from ..utils.logger import get_logger

log = get_logger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────────

MAGIC   = b'SENC'
VERSION = 0x01

# Argon2id parameters — tuned ~1-2 s on modern hardware (OWASP 2023)
ARGON2_MEMORY = 131072   # 128 MB
ARGON2_TIME   = 3
ARGON2_PARA   = 4
ARGON2_LEN    = 32       # 256-bit derived key

SALT_LEN  = 32   # 256-bit random salt
NONCE_LEN = 12   # 96-bit GCM nonce
TAG_LEN   = 16   # 128-bit GCM authentication tag

CHUNK_SIZE    = 64 * 1024   # 64 KB — streaming chunk size
MAX_FNAME_LEN = 255         # maximum allowed filename length in header


# ─── Exceptions ──────────────────────────────────────────────────────────────

class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    pass


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _derive_key(password: bytes, salt: bytes,
                mem: int, time: int, para: int, length: int) -> bytes:
    """Dérive une clé cryptographique depuis le mot de passe via Argon2id."""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time,
        memory_cost=mem,
        parallelism=para,
        hash_len=length,
        type=Type.ID,
    )


def _make_aad(mem: int, time: int, para: int, length: int, filename: str) -> bytes:
    """
    Construit les données supplémentaires authentifiées (AAD) pour GCM.

    Inclut les paramètres Argon2id afin que toute modification d'en-tête
    (ex. attaque par rétrogradation de mem) soit détectée et rejetée par GCM.
    """
    params_bytes = struct.pack('>IIIB', mem, time, para, length)
    return params_bytes + filename.encode('utf-8')


def _build_header(salt: bytes, nonce: bytes, filename: str) -> bytes:
    """Construit l'en-tête du fichier chiffré."""
    fname = filename.encode('utf-8')
    params = struct.pack('>IIIB', ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARA, ARGON2_LEN)
    return (
        MAGIC +
        bytes([VERSION]) +
        params +                          # 13 bytes
        salt +                            # 32 bytes
        nonce +                           # 12 bytes
        struct.pack('>H', len(fname)) +   # 2 bytes
        fname
    )


def _parse_header(data: bytes) -> dict:
    """Analyse et valide l'en-tête du fichier chiffré."""
    if len(data) < 64:
        raise DecryptionError("Fichier trop court ou corrompu.")
    if data[:4] != MAGIC:
        raise DecryptionError(
            "Format invalide — ce n'est pas un fichier .senc.\n"
            "Vérifiez que le fichier n'est pas corrompu."
        )
    version = data[4]
    if version != VERSION:
        raise DecryptionError(
            f"Version non supportée : {version}. "
            "Mettez secure-encrypto à jour."
        )

    off = 5
    mem, time, para, length = struct.unpack('>IIIB', data[off:off + 13])
    off += 13
    salt  = data[off:off + SALT_LEN];  off += SALT_LEN
    nonce = data[off:off + NONCE_LEN]; off += NONCE_LEN

    if off + 2 > len(data):
        raise DecryptionError("En-tête tronqué — fichier corrompu.")

    flen = struct.unpack('>H', data[off:off + 2])[0]
    off += 2

    # Validate FNAME_LEN before any data access to prevent overread / IndexError
    if flen > MAX_FNAME_LEN:
        raise DecryptionError(
            f"FNAME_LEN ({flen}) dépasse le maximum autorisé ({MAX_FNAME_LEN}) — "
            "fichier corrompu ou malveillant."
        )
    if off + flen > len(data):
        raise DecryptionError("En-tête tronqué — fichier corrompu.")

    try:
        fname = data[off:off + flen].decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise DecryptionError("Nom de fichier invalide — fichier corrompu ou malveillant.")
    off += flen

    return {
        'version': version,
        'mem': mem, 'time': time, 'para': para, 'length': length,
        'salt': salt, 'nonce': nonce,
        'filename': fname,
        'offset': off,
    }


# ─── Public API ───────────────────────────────────────────────────────────────

class CryptoEngine:
    """
    Moteur de chiffrement/déchiffrement sans état.
    Toutes les opérations sont thread-safe (aucun état partagé).
    """

    @staticmethod
    def encrypt_file(
        input_path: str,
        output_path: str,
        password: str,
        progress_cb: Optional[Callable[[float], None]] = None,
    ) -> None:
        path = Path(input_path)
        log.info("Début du chiffrement : %s -> %s", input_path, output_path)

        if path.is_dir():
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
                tmp_path = tmp.name
            try:
                if progress_cb:
                    progress_cb(0.1)
                with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                    for child in sorted(path.rglob('*')):
                        zf.write(child, child.relative_to(path.parent))
                if progress_cb:
                    progress_cb(0.3)
                CryptoEngine._encrypt_bytes(
                    tmp_path, output_path, password,
                    path.name + '.zip', progress_cb,
                    start_at=0.3,
                )
            finally:
                # secure_delete efface le ZIP en clair (3 passes), pas une simple suppression
                try:
                    secure_delete(tmp_path)
                except Exception:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        else:
            CryptoEngine._encrypt_bytes(
                input_path, output_path, password,
                path.name, progress_cb,
            )

    @staticmethod
    def _encrypt_bytes(
        input_path: str,
        output_path: str,
        password: str,
        original_name: str,
        progress_cb: Optional[Callable[[float], None]] = None,
        start_at: float = 0.0,
    ) -> None:
        salt  = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)

        if progress_cb:
            progress_cb(start_at + 0.1)

        key = _derive_key(
            password.encode('utf-8'), salt,
            ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARA, ARGON2_LEN,
        )

        if progress_cb:
            progress_cb(start_at + 0.5)

        # L'AAD inclut les params Argon2 — toute altération de l'en-tête casse l'auth GCM
        aad = _make_aad(ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARA, ARGON2_LEN, original_name)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend(),
        ).encryptor()
        encryptor.authenticate_additional_data(aad)

        header = _build_header(salt, nonce, original_name)

        try:
            # Lecture en flux par blocs de 64 Ko — pas de chargement complet en RAM
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                fout.write(header)
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    fout.write(encryptor.update(chunk))
                fout.write(encryptor.finalize())
                fout.write(encryptor.tag)   # 16-byte GCM tag appended at end
        except Exception as e:
            try:
                os.unlink(output_path)
            except OSError:
                pass
            raise EncryptionError(f"Erreur de chiffrement AES-GCM : {e}")

        log.info('Fin du chiffrement : %s', output_path)
        if progress_cb:
            progress_cb(1.0)

    @staticmethod
    def decrypt_file(
        input_path: str,
        output_dir: str,
        password: str,
        progress_cb: Optional[Callable[[float], None]] = None,
    ) -> str:
        log.info('Début du déchiffrement : %s', input_path)
        # Déchiffrement en flux — le fichier complet n'est jamais chargé en RAM
        file_size = os.path.getsize(input_path)
        header_read_size = 64 + MAX_FNAME_LEN + 4   # generous upper bound

        with open(input_path, 'rb') as f:
            header_data = f.read(header_read_size)

        if progress_cb:
            progress_cb(0.2)

        hdr = _parse_header(header_data)
        data_offset = hdr['offset']

        # Taille minimale valide : en-tête + tag GCM de 16 octets
        if file_size - data_offset < TAG_LEN:
            raise DecryptionError("Fichier trop court ou corrompu.")

        ciphertext_len = file_size - data_offset - TAG_LEN

        # Lecture du tag GCM depuis les derniers TAG_LEN octets du fichier
        with open(input_path, 'rb') as f:
            f.seek(file_size - TAG_LEN)
            tag = f.read(TAG_LEN)

        MIN_MEM, MAX_MEM = 8192, 1048576
        MIN_TIME, MAX_TIME = 1, 100
        MIN_PARA, MAX_PARA = 1, 16
        MIN_LEN, MAX_LEN = 16, 64

        if not (MIN_MEM <= hdr['mem'] <= MAX_MEM):
            raise DecryptionError("Paramètre Argon2id mémoire invalide.")
        if not (MIN_TIME <= hdr['time'] <= MAX_TIME):
            raise DecryptionError("Paramètre Argon2id time_cost invalide.")
        if not (MIN_PARA <= hdr['para'] <= MAX_PARA):
            raise DecryptionError("Paramètre Argon2id parallelism invalide.")
        if not (MIN_LEN <= hdr['length'] <= MAX_LEN):
            raise DecryptionError("Paramètre Argon2id longueur invalide.")

        key = _derive_key(
            password.encode('utf-8'), hdr['salt'],
            hdr['mem'], hdr['time'], hdr['para'], hdr['length'],
        )

        if progress_cb:
            progress_cb(0.7)

        # L'AAD doit correspondre exactement à celui utilisé lors du chiffrement
        aad = _make_aad(hdr['mem'], hdr['time'], hdr['para'], hdr['length'], hdr['filename'])

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(hdr['nonce'], tag),
            backend=default_backend(),
        ).decryptor()
        decryptor.authenticate_additional_data(aad)

        safe_name = Path(hdr['filename']).name
        out_path = str(Path(output_dir) / safe_name)
        tmp_path = out_path + '.tmp'

        try:
            with open(input_path, 'rb') as fin, open(tmp_path, 'wb') as fout:
                fin.seek(data_offset)
                remaining = ciphertext_len
                while remaining > 0:
                    chunk = fin.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    fout.write(decryptor.update(chunk))
                    remaining -= len(chunk)

            # finalize() lève InvalidTag si l'authentification GCM échoue
            decryptor.finalize()
            os.replace(tmp_path, out_path)

        except InvalidTag:
            log.error('Échec GCM authentication (InvalidTag) : %s', input_path)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise DecryptionError(
                "Mot de passe incorrect ou fichier corrompu.\n"
                "L'authentification GCM a échoué — intégrité compromise."
            )
        except DecryptionError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        except Exception as e:
            log.error('Erreur lors du déchiffrement de %s : %s', input_path, e)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise DecryptionError(f"Erreur lors du déchiffrement : {e}")

        if progress_cb:
            progress_cb(0.95)

        if hdr['filename'].endswith('.zip'):
            extract_dir = os.path.join(output_dir, Path(hdr['filename']).stem)
            os.makedirs(extract_dir, exist_ok=True)
            try:
                with zipfile.ZipFile(out_path, 'r') as zf:
                    # ZIP Slip prevention: verify every member stays inside extract_dir
                    extract_dir_abs = Path(extract_dir).resolve()
                    for member in zf.infolist():
                        member_target = (extract_dir_abs / member.filename).resolve()
                        try:
                            member_target.relative_to(extract_dir_abs)
                        except ValueError:
                            log.error('ZIP Slip détecté dans %s — membre : %s', input_path, member.filename)
                            raise DecryptionError(
                                "ZIP Slip détecté — chemin malveillant dans l'archive.\n"
                                "Extraction annulée pour protéger le système."
                            )
                        zf.extract(member, extract_dir)
                os.remove(out_path)
                out_path = extract_dir
            except zipfile.BadZipFile:
                pass

        log.info('Fin du déchiffrement : %s', out_path)
        if progress_cb:
            progress_cb(1.0)

        return out_path

    @staticmethod
    def get_file_info(input_path: str) -> dict:
        read_size = 64 + MAX_FNAME_LEN + 4
        with open(input_path, 'rb') as f:
            data = f.read(read_size)
        try:
            hdr = _parse_header(data)
            return {
                'valid': True,
                'version': hdr['version'],
                'original_name': hdr['filename'],
                'argon2_memory_mb': hdr['mem'] // 1024,
                'argon2_time_cost': hdr['time'],
                'argon2_parallelism': hdr['para'],
                'encrypted_size': os.path.getsize(input_path),
            }
        except DecryptionError as e:
            return {'valid': False, 'error': str(e)}
