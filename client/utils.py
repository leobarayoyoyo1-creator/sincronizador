def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_eta(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.0f}min"
    return f"{minutes / 60:.1f}h"


def is_name_safe(name: str) -> bool:
    """Verifica que um nome de membro de tar não escapa do destino."""
    return not name.startswith("/") and ".." not in name.split("/")
