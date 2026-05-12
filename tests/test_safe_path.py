"""Testes para _safe_path — usa um BASE_DIR temporário."""


import server


def test_safe_path_inside_base(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "BASE_DIR", tmp_path)
    target = tmp_path / "sub" / "dir"
    target.mkdir(parents=True)
    result = server._safe_path(str(target))
    assert result == target.resolve()


def test_safe_path_equals_base(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "BASE_DIR", tmp_path)
    result = server._safe_path(str(tmp_path))
    assert result == tmp_path.resolve()


def test_safe_path_outside_base(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "BASE_DIR", tmp_path / "allowed")
    (tmp_path / "allowed").mkdir()
    outside = tmp_path / "other"
    outside.mkdir()
    assert server._safe_path(str(outside)) is None


def test_safe_path_traversal_attempt(tmp_path, monkeypatch):
    base = tmp_path / "base"
    base.mkdir()
    monkeypatch.setattr(server, "BASE_DIR", base)
    attempt = str(base / ".." / "etc")
    assert server._safe_path(attempt) is None


def test_safe_path_empty():
    assert server._safe_path("") is None


def test_safe_path_none_input():
    assert server._safe_path(None) is None  # type: ignore[arg-type]


def test_is_name_safe_server_matches_client():
    """Garante que server._is_name_safe e client.utils.is_name_safe se comportam igual."""
    from client.utils import is_name_safe as client_is
    cases = ["ok.txt", "a/b.txt", "/abs", "../x", "a/../b", "..", "a/..", "normal.tar.gz"]
    for c in cases:
        assert server._is_name_safe(c) == client_is(c), f"divergência em {c!r}"
