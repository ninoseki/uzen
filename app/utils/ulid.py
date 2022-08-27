from app import types


def get_ulid() -> types.ULID:
    return types.ULID()


def get_ulid_str() -> str:
    return str(types.ULID())
