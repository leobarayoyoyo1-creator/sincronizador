from client.sync_logic import _diff_manifest, _make_batches


def test_diff_manifest_empty_local(tmp_path):
    manifest = [
        {"path": "a.txt", "size": 10, "mtime": 100.0},
        {"path": "b.txt", "size": 20, "mtime": 200.0},
    ]
    result = _diff_manifest(manifest, tmp_path)
    assert len(result) == 2


def test_diff_manifest_all_match(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"x" * 10)
    import os
    os.utime(tmp_path / "a.txt", (100.0, 100.0))
    manifest = [{"path": "a.txt", "size": 10, "mtime": 100.0}]
    assert _diff_manifest(manifest, tmp_path) == []


def test_diff_manifest_size_differs(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"x" * 5)
    manifest = [{"path": "a.txt", "size": 10, "mtime": 100.0}]
    result = _diff_manifest(manifest, tmp_path)
    assert len(result) == 1


def test_diff_manifest_mtime_within_tolerance(tmp_path):
    """mtime dentro da tolerância (2s) é considerado igual."""
    import os
    (tmp_path / "a.txt").write_bytes(b"x" * 10)
    os.utime(tmp_path / "a.txt", (101.0, 101.0))
    manifest = [{"path": "a.txt", "size": 10, "mtime": 100.0}]
    assert _diff_manifest(manifest, tmp_path) == []


def test_diff_manifest_mtime_outside_tolerance(tmp_path):
    import os
    (tmp_path / "a.txt").write_bytes(b"x" * 10)
    os.utime(tmp_path / "a.txt", (200.0, 200.0))
    manifest = [{"path": "a.txt", "size": 10, "mtime": 100.0}]
    assert len(_diff_manifest(manifest, tmp_path)) == 1


def test_make_batches_by_count():
    items = list(range(25))
    batches = _make_batches(items, max_count=10, max_bytes=10**9, size_fn=lambda _: 1)
    assert [len(b) for b in batches] == [10, 10, 5]


def test_make_batches_by_bytes():
    items = [("a", 0, 30), ("b", 0, 30), ("c", 0, 30), ("d", 0, 30)]
    batches = _make_batches(items, max_count=999, max_bytes=70, size_fn=lambda it: it[2])
    assert all(sum(it[2] for it in b) <= 70 or len(b) == 1 for b in batches)
    assert sum(len(b) for b in batches) == 4


def test_make_batches_empty():
    assert _make_batches([], 10, 1000, lambda _: 1) == []


def test_make_batches_single_huge_item():
    """Item sozinho maior que max_bytes ainda vai em batch próprio."""
    items = [("big", 0, 10**9)]
    batches = _make_batches(items, max_count=10, max_bytes=100, size_fn=lambda it: it[2])
    assert len(batches) == 1
    assert batches[0] == items
