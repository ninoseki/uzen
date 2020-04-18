from tortoise import fields
from tortoise.models import Model


class AbstractBaseModel(Model):
    id = fields.IntField(pk=True)

    @classmethod
    async def delete_by_id(cls, id_: int) -> None:
        await cls.get(id=id_).delete()

    class Meta:
        abstract = True
