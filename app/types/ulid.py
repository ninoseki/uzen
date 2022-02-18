import re
from typing import Any, Dict

from pydantic import ConstrainedStr
from ulid import ULID as _ULID
from ulid import base32

_ulid_hash_obj = object()


class ULID(_ULID, ConstrainedStr):
    strip_whitespace = True
    min_length = 26
    max_length = 26
    regex = re.compile(
        r"^[0123456789abcdefghjkmnpqrstvwxyzABCDEFGHJKMNPQRSTVWXYZ]{26}$"
    )

    def __new__(cls, *args, **kwargs) -> "ULID":
        if not args:
            args = (_ULID(),)

        return super().__new__(cls, *args, **kwargs)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(base32.decode(self), *args[1:], **kwargs)

    def __hash__(self) -> int:
        return hash((_ulid_hash_obj, self.bytes))

    @classmethod
    def __modify_schema__(cls, field_schema: Dict[str, Any]) -> None:
        # using string as the default type as it's the natural type when encoding to JSON
        super().__modify_schema__(field_schema)
        field_schema["format"] = "ulid"

    @classmethod
    def validate(cls, value: Any):
        return cls(super().validate(value))

    @classmethod
    def from_bytes(cls, bytes_: bytes) -> "ULID":
        return cls(_ULID.from_bytes(bytes_))

    @classmethod
    def from_str(cls, string: str) -> "ULID":
        return cls(string)
