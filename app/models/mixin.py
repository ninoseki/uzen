from typing import Union

from tortoise.fields.data import DatetimeField

from app import types


class TimestampMixin:
    created_at = DatetimeField(auto_now_add=True)


class DeleteMixin:
    @classmethod
    async def delete_by_id(cls, id_: Union[str, types.ULID]) -> None:
        await cls.get(id=str(id_)).delete()


class CountMixin:
    @classmethod
    async def count(cls) -> int:
        return await cls.all().count()
