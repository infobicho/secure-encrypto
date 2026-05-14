"""
Tests for secure_encrypto.core.engine
======================================
Covers:
  - Encrypt then decrypt (round-trip)
  - Wrong password fails with DecryptionError
  - ZIP Slip detection
  - FNAME_LEN validation in _parse_header
  - _parse_header: corrupted magic, unknown version, flen too large
"""

import os
import struct
import zipfile
import tempfile
import pytest

from secure_encrypto.core.engine import (
    CryptoEngine,
    DecryptionError,
    EncryptionError,
    _parse_header,
    MAGIC,
    VERSION,
    SALT_LEN,
    NONCE_LEN,
    ARGON2_MEMORY,
    ARGON2_TIME,
    ARGON2_PARA,
    ARGON2_LEN,
    MAX_FNAME_LEN,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path):
    """Return a temporary directory path (str)."""
    return str(tmp_path)


@pytest.fixture
def plaintext_file(tmp_path):
    """Create a small plaintext file and return its path."""
    p = tmp_path / "hello.txt"
    p.write_bytes(b"Hello, secure-encrypto! " * 100)
    return str(p)


@pytest.fixture
def encrypted_file(plaintext_file, tmp_path):
    """Encrypt plaintext_file with password 'correct_pw' and return output path."""
    out = str(tmp_path / "hello.txt.senc")
    CryptoEngine.encrypt_file(plaintext_file, out, "correct_pw")
    return out


# ─── Round-trip ──────────────────────────────────────────────────────────────

class TestRoundTrip:
    def test_encrypt_creates_output(self, encrypted_file):
        assert os.path.exists(encrypted_file)
        assert os.path.getsize(encrypted_file) > 0

    def test_decrypt_restores_content(self, plaintext_file, encrypted_file, tmp_path):
        out_dir = str(tmp_path / "out")
        os.makedirs(out_dir)
        restored = CryptoEngine.decrypt_file(encrypted_file, out_dir, "correct_pw")
        original_bytes = open(plaintext_file, "rb").read()
        restored_bytes = open(restored, "rb").read()
        assert restored_bytes == original_bytes

    def test_decrypt_preserves_filename(self, encrypted_file, tmp_path):
        out_dir = str(tmp_path / "out2")
        os.makedirs(out_dir)
        restored = CryptoEngine.decrypt_file(encrypted_file, out_dir, "correct_pw")
        assert os.path.basename(restored) == "hello.txt"


# ─── Wrong password ───────────────────────────────────────────────────────────

class TestWrongPassword:
    def test_wrong_password_raises(self, encrypted_file, tmp_path):
        out_dir = str(tmp_path / "wrong")
        os.makedirs(out_dir)
        with pytest.raises(DecryptionError):
            CryptoEngine.decrypt_file(encrypted_file, out_dir, "wrong_password")

    def test_empty_password_raises(self, encrypted_file, tmp_path):
        out_dir = str(tmp_path / "empty")
        os.makedirs(out_dir)
        with pytest.raises(DecryptionError):
            CryptoEngine.decrypt_file(encrypted_file, out_dir, "")

    def test_no_tmp_file_left_after_failure(self, encrypted_file, tmp_path):
        out_dir = str(tmp_path / "cleanup")
        os.makedirs(out_dir)
        with pytest.raises(DecryptionError):
            CryptoEngine.decrypt_file(encrypted_file, out_dir, "bad_pw")
        tmp_files = [f for f in os.listdir(out_dir) if f.endswith(".tmp")]
        assert tmp_files == []


# ─── ZIP Slip ─────────────────────────────────────────────────────────────────

class TestZipSlip:
    """
    Build a .senc file that contains a ZIP with a path-traversal member,
    then verify that decrypt_file raises DecryptionError with the ZIP Slip message.
    """

    def _make_malicious_senc(self, tmp_path, password="testpw"):
        """
        Create a ZIP containing a path-traversal entry, encrypt it, return the .senc path.
        We create the ZIP manually then encrypt it.
        """
        zip_path = str(tmp_path / "evil.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            # Standard entry first
            zf.writestr("safe.txt", "safe content")
            # Traversal entry: ../../evil.txt
            info = zipfile.ZipInfo("../../evil.txt")
            zf.writestr(info, "evil content")

        senc_path = str(tmp_path / "evil.senc")
        # Encrypt the zip directly so it gets the .zip suffix treatment on decrypt
        CryptoEngine._encrypt_bytes(
            zip_path, senc_path, password, "evil.zip"
        )
        return senc_path

    def test_zip_slip_detected(self, tmp_path):
        senc = self._make_malicious_senc(tmp_path)
        out_dir = str(tmp_path / "extract")
        os.makedirs(out_dir)
        with pytest.raises(DecryptionError, match="ZIP Slip"):
            CryptoEngine.decrypt_file(senc, out_dir, "testpw")


# ─── _parse_header ────────────────────────────────────────────────────────────

class TestParseHeader:

    def _valid_header(self, fname="file.txt"):
        """Build a syntactically correct header bytes."""
        fname_bytes = fname.encode("utf-8")
        params = struct.pack(">IIIB", ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARA, ARGON2_LEN)
        salt  = b"\x00" * SALT_LEN
        nonce = b"\x00" * NONCE_LEN
        return (
            MAGIC
            + bytes([VERSION])
            + params
            + salt
            + nonce
            + struct.pack(">H", len(fname_bytes))
            + fname_bytes
            # Append dummy ciphertext so file isn't "too short"
            + b"\x00" * 32
        )

    def test_valid_header_parses(self):
        data = self._valid_header("document.pdf")
        hdr = _parse_header(data)
        assert hdr["filename"] == "document.pdf"
        assert hdr["version"] == VERSION

    def test_too_short_raises(self):
        with pytest.raises(DecryptionError):
            _parse_header(b"\x00" * 10)

    def test_bad_magic_raises(self):
        data = b"EVIL" + self._valid_header()[4:]
        with pytest.raises(DecryptionError, match="Format invalide"):
            _parse_header(data)

    def test_unknown_version_raises(self):
        data = bytearray(self._valid_header())
        data[4] = 0xFF  # Replace version byte
        with pytest.raises(DecryptionError, match="Version non support"):
            _parse_header(bytes(data))

    def test_flen_too_large_raises(self):
        """FNAME_LEN set to MAX_FNAME_LEN + 1 must be rejected."""
        fname_bytes = b"x" * (MAX_FNAME_LEN + 1)
        params = struct.pack(">IIIB", ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARA, ARGON2_LEN)
        salt  = b"\x00" * SALT_LEN
        nonce = b"\x00" * NONCE_LEN
        data = (
            MAGIC
            + bytes([VERSION])
            + params
            + salt
            + nonce
            + struct.pack(">H", MAX_FNAME_LEN + 1)
            + fname_bytes
            + b"\x00" * 32
        )
        with pytest.raises(DecryptionError, match="FNAME_LEN"):
            _parse_header(data)

    def test_flen_zero_is_valid(self):
        """Empty filename (flen=0) is technically valid — should not raise."""
        params = struct.pack(">IIIB", ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARA, ARGON2_LEN)
        salt  = b"\x00" * SALT_LEN
        nonce = b"\x00" * NONCE_LEN
        data = (
            MAGIC
            + bytes([VERSION])
            + params
            + salt
            + nonce
            + struct.pack(">H", 0)  # flen = 0
            + b"\x00" * 32
        )
        hdr = _parse_header(data)
        assert hdr["filename"] == ""

    def test_truncated_after_flen_raises(self):
        """Header claims flen=50 but data ends before those bytes."""
        params = struct.pack(">IIIB", ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARA, ARGON2_LEN)
        salt  = b"\x00" * SALT_LEN
        nonce = b"\x00" * NONCE_LEN
        data = (
            MAGIC
            + bytes([VERSION])
            + params
            + salt
            + nonce
            + struct.pack(">H", 50)
            + b"x" * 10  # only 10 bytes instead of 50
        )
        with pytest.raises(DecryptionError):
            _parse_header(data)


# ─── get_file_info ────────────────────────────────────────────────────────────

class TestGetFileInfo:
    def test_valid_senc_returns_info(self, encrypted_file):
        info = CryptoEngine.get_file_info(encrypted_file)
        assert info["valid"] is True
        assert info["original_name"] == "hello.txt"
        assert info["argon2_memory_mb"] == ARGON2_MEMORY // 1024

    def test_invalid_file_returns_error(self, tmp_path):
        bad = str(tmp_path / "bad.senc")
        with open(bad, "wb") as f:
            f.write(b"GARBAGE" * 20)
        info = CryptoEngine.get_file_info(bad)
        assert info["valid"] is False
        assert "error" in info
