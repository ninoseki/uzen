from tortoise import fields


class TimestampMixin:
    created_at = fields.DatetimeField(auto_now_add=True)


class DeleteMixin:
    @classmethod
    async def delete_by_id(cls, id_: str) -> None:
        await cls.get(id=id_).delete()


class CountMixin:
    @classmethod
    async def count(cls) -> int:
        return await cls.all().count()
