"""
Suppression sécurisée de fichiers — 3 passes d'écrasement.
Remarque : la suppression intraçable dépend du système d'exploitation, du système
de fichiers et du matériel de stockage. Le wear-leveling SSD peut conserver des
données au-delà de ce que le logiciel peut contrôler. Seul le chiffrement intégral
du disque (LUKS, BitLocker) offre une protection totale.
"""

import os
from pathlib import Path


def secure_delete(path: str, passes: int = 3) -> None:
    """
    Supprime un fichier ou un répertoire de manière sécurisée.
    Écrase le contenu avec 0x00, 0xFF, puis des données aléatoires avant suppression.
    """
    p = Path(path)
    if p.is_dir():
        _secure_delete_dir(p, passes)
    elif p.is_file():
        _wipe_file(str(p), passes)
        os.remove(str(p))
    else:
        raise FileNotFoundError(f"Chemin introuvable : {path}")


def _secure_delete_dir(root: Path, passes: int) -> None:
    """Écrase récursivement tous les fichiers, puis supprime les répertoires."""
    # Wipe all files first
    for child in root.rglob('*'):
        if child.is_file():
            _wipe_file(str(child), passes)
            os.remove(str(child))
    # Remove directories bottom-up
    for child in sorted(root.rglob('*'), reverse=True):
        if child.is_dir():
            try:
                child.rmdir()
            except OSError:
                pass
    root.rmdir()


def _wipe_file(path: str, passes: int) -> None:
    """Écrase le contenu du fichier avec plusieurs motifs."""
    size = os.path.getsize(path)
    if size == 0:
        return

    try:
        with open(path, 'r+b') as f:
            for i in range(passes):
                f.seek(0)
                if i == 0:
                    f.write(b'\x00' * size)   # Passe 1 : zéros
                elif i == 1:
                    f.write(b'\xff' * size)   # Passe 2 : uns (0xFF)
                else:
                    # Passe 3+ : données aléatoires cryptographiques
                    written = 0
                    chunk = 65536
                    while written < size:
                        to_write = min(chunk, size - written)
                        f.write(os.urandom(to_write))
                        written += to_write
                f.flush()
                os.fsync(f.fileno())
    except (IOError, OSError):
        pass   # Suppression en mode best-effort — le fichier sera quand même supprimé
