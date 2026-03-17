import json
import os
import sys

from .constants import CONFIG_FILE


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(data: dict):
    current = load_config()
    current.update(data)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2)
    # Protege o arquivo em sistemas Unix (não aplicável no Windows)
    if sys.platform != "win32":
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass
