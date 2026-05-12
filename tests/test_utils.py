from client.utils import fmt_bytes, fmt_eta, fmt_speed, is_name_safe


def test_fmt_bytes_units():
    assert fmt_bytes(0) == "0 B"
    assert fmt_bytes(1023) == "1023 B"
    assert fmt_bytes(1024) == "1 KB"
    assert fmt_bytes(1024 * 1024) == "1 MB"
    assert fmt_bytes(1024**3) == "1 GB"
    assert "TB" in fmt_bytes(1024**4)


def test_fmt_speed():
    assert fmt_speed(1024) == "1 KB/s"


def test_fmt_eta_seconds():
    assert fmt_eta(0) == "0s"
    assert fmt_eta(59) == "59s"


def test_fmt_eta_minutes():
    assert fmt_eta(60) == "1min"
    assert fmt_eta(3000) == "50min"


def test_fmt_eta_hours():
    assert fmt_eta(3600) == "1.0h"
    assert fmt_eta(7200) == "2.0h"


def test_is_name_safe_normal():
    assert is_name_safe("file.txt")
    assert is_name_safe("sub/file.txt")
    assert is_name_safe("a/b/c/d.bin")


def test_is_name_safe_blocks_absolute():
    assert not is_name_safe("/etc/passwd")
    assert not is_name_safe("/file.txt")


def test_is_name_safe_blocks_traversal():
    assert not is_name_safe("../file")
    assert not is_name_safe("a/../b")
    assert not is_name_safe("..")
    assert not is_name_safe("a/..")


def test_is_name_safe_allows_dotted_names():
    """Nomes com '.' no meio são válidos; só '..' como componente bloqueia."""
    assert is_name_safe("file.tar.gz")
    assert is_name_safe(".hidden")
    assert is_name_safe("a.b/c.d")
