"""
secure_encrypto.utils.logger
=============================
Configures a rotating file logger saved to:
    ~/.config/secure-encrypto/secure-encrypto.log

Usage anywhere in the project:
    from secure_encrypto.utils.logger import get_logger
    log = get_logger(__name__)
    log.info("Début du chiffrement : %s", filename)
    log.error("Échec de déchiffrement : %s", error)
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

LOG_DIR      = Path.home() / ".config" / "secure-encrypto"
LOG_FILE     = LOG_DIR / "secure-encrypto.log"
MAX_BYTES    = 2 * 1024 * 1024   # 2 MB per file
BACKUP_COUNT = 3                  # Keep 3 rotated files
LOG_FORMAT   = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
DATE_FORMAT  = "%Y-%m-%d %H:%M:%S"

# ─── Internal state ───────────────────────────────────────────────────────────

_configured = False


def _configure() -> None:
    """One-time setup: create log directory and attach handlers to root logger."""
    global _configured
    if _configured:
        return

    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        # If we can't create the directory (permissions, read-only FS…)
        # fall back to stderr-only logging rather than crashing the app.
        pass

    root = logging.getLogger("secure_encrypto")
    root.setLevel(logging.DEBUG)

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # ── Rotating file handler ────────────────────────────────────────────
    try:
        fh = RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        root.addHandler(fh)
    except OSError:
        # Can't open log file — degrade gracefully (stderr only)
        pass

    # ── Console handler (WARNING+ only, so normal runs stay quiet) ───────
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # Avoid propagation to root Python logger (prevents duplicate output)
    root.propagate = False

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger scoped under the 'secure_encrypto' namespace.

    Example:
        log = get_logger(__name__)
        log.info("Chiffrement démarré : %s", path)
    """
    _configure()
    # Always prefix with 'secure_encrypto' so all app loggers share the handler
    if not name.startswith("secure_encrypto"):
        name = f"secure_encrypto.{name}"
    return logging.getLogger(name)
