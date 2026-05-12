import io

from server import _LimitedReader


def test_limited_reader_under_limit():
    data = b"hello world"
    r = _LimitedReader(io.BytesIO(data), limit=100)
    assert r.read(5) == b"hello"
    assert r.read() == b" world"
    assert r.read() == b""


def test_limited_reader_at_limit():
    data = b"x" * 50
    r = _LimitedReader(io.BytesIO(data), limit=50)
    assert r.read() == data
    assert r.read() == b""


def test_limited_reader_caps_at_limit():
    data = b"x" * 100
    r = _LimitedReader(io.BytesIO(data), limit=50)
    out = r.read()
    assert len(out) == 50


def test_limited_reader_caps_chunked():
    data = b"abcdefghij"
    r = _LimitedReader(io.BytesIO(data), limit=4)
    chunks = []
    while chunk := r.read(2):
        chunks.append(chunk)
    assert b"".join(chunks) == b"abcd"


def test_limited_reader_zero_limit():
    r = _LimitedReader(io.BytesIO(b"data"), limit=0)
    assert r.read() == b""
    assert r.read(10) == b""
