"""Logging persistido em arquivo para o cliente."""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def log_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "Sincronizador"
    return Path.home() / ".sincronizador"


def setup_file_logging() -> Path:
    """Configura logger 'sincronizador' com RotatingFileHandler. Retorna o caminho."""
    d = log_dir()
    d.mkdir(parents=True, exist_ok=True)
    log_file = d / "client.log"

    handler = RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    root = logging.getLogger("sincronizador")
    root.setLevel(logging.INFO)
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)

    return log_file


def get_logger() -> logging.Logger:
    return logging.getLogger("sincronizador")
