from server import _hash_password, _verify_password


def test_hash_format():
    h = _hash_password("senha123")
    salt_hex, dk_hex = h.split(":", 1)
    assert len(bytes.fromhex(salt_hex)) == 32
    assert len(bytes.fromhex(dk_hex)) == 32


def test_verify_correct():
    h = _hash_password("minha senha forte!")
    assert _verify_password("minha senha forte!", h)


def test_verify_incorrect():
    h = _hash_password("certa")
    assert not _verify_password("errada", h)


def test_verify_empty_against_real():
    h = _hash_password("a")
    assert not _verify_password("", h)


def test_different_salts_different_hashes():
    a = _hash_password("igual")
    b = _hash_password("igual")
    assert a != b
    assert _verify_password("igual", a)
    assert _verify_password("igual", b)


def test_unicode_password():
    h = _hash_password("açúcar 🔐")
    assert _verify_password("açúcar 🔐", h)
    assert not _verify_password("açúcar", h)


def test_legacy_sha256_fallback():
    import hashlib
    legacy = hashlib.sha256(b"velha").hexdigest()
    assert _verify_password("velha", legacy)
    assert not _verify_password("nova", legacy)
