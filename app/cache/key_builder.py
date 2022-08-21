import hashlib


def default_key_builder(
    func,
    *args,
    **kwargs,
) -> str:
    return hashlib.md5(  # nosec:B303
        f"{func.__module__}:{func.__name__}:{args}:{kwargs}".encode()
    ).hexdigest()
