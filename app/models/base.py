from uuid import UUID

from tortoise import fields
from tortoise.models import Model


class AbstractBaseModel(Model):
    id = fields.UUIDField(pk=True)

    @classmethod
    async def delete_by_id(cls, id_: UUID) -> None:
        await cls.get(id=id_).delete()

    @classmethod
    async def count(cls) -> int:
        return await cls.all().count()

    class Meta:
        abstract = True


class AbstractResourceModel(Model):
    id = fields.CharField(max_length=64, pk=True)
    content = fields.TextField()

    @classmethod
    async def delete_by_id(cls, id_: str) -> None:
        await cls.get(id=id_).delete()

    @classmethod
    async def count(cls) -> int:
        return await cls.all().count()

    class Meta:
        abstract = True
