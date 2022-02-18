from typing import Any, Optional, Type, Union

from tortoise import Model
from tortoise.fields import Field

from app import types


class ULIDField(Field, types.ULID):

    SQL_TYPE = "CHAR(26)"

    def __init__(self, **kwargs: Any) -> None:
        if kwargs.get("pk", False) and "default" not in kwargs:
            kwargs["default"] = types.ULID

        super().__init__(**kwargs)

    def to_db_value(
        self, value: Any, instance: "Union[Type[Model], Model]"
    ) -> Optional[str]:
        if value is None:
            return None

        return str(value)

    def to_python_value(self, value: Any) -> Optional[types.ULID]:
        if value is None:
            return None

        if isinstance(value, types.ULID):
            return value

        return types.ULID.from_str(value)
