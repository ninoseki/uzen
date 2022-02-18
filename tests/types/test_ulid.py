from app.types import ULID


def test_ulid():
    a = ULID()
    assert len(str(a)) == 26

    b = ULID()
    assert str(a) != str(b)


def test_ulid_from_str():
    a = ULID()

    b = ULID.from_str(str(a))
    assert str(a) == str(b)
