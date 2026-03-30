import os
import sys
from pathlib import Path

# Suporta execução compilada com PyInstaller
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).parent
else:
    APP_DIR = Path(__file__).resolve().parent.parent

CONFIG_FILE = APP_DIR / "config.json"

PARALLEL_WORKERS = 16
ARCHIVE_THRESHOLD = 3
ARCHIVE_BATCH_SIZE = 800
ARCHIVE_BATCH_MAX_BYTES = 50 * 1024 * 1024   # 50 MB por lote
CHUNK_SIZE = 524_288          # 512 KB
MTIME_TOLERANCE = 2           # segundos
ZSTD_LEVEL = 1
ZSTD_THREADS = min(os.cpu_count() or 1, 8)
MAX_LOG_LINES = 500
