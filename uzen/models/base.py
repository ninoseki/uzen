from uuid import UUID

from tortoise import fields
from tortoise.models import Model


class AbstractBaseModel(Model):
    id = fields.UUIDField(pk=True)

    @classmethod
    async def delete_by_id(cls, id_: UUID) -> None:
        await cls.get(id=id_).delete()

    class Meta:
        abstract = True
