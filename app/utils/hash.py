import hashlib
from typing import Union

import ppdeep


def string_encode_as_bytes(
    input_string: Union[str, bytes], encoding: str = "utf-8", **kwargs
):
    if isinstance(input_string, str):
        return input_string.encode(encoding, **kwargs)
    else:
        return input_string


def ssdeep(input_string: Union[str, bytes]) -> str:
    """."""
    return ppdeep.hash(string_encode_as_bytes(input_string))


def sha256(input_string: Union[str, bytes]) -> str:
    return hashlib.sha256(string_encode_as_bytes(input_string)).hexdigest()
