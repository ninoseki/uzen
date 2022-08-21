from app import types


def get_ulid_str() -> str:
    return str(types.ULID())
