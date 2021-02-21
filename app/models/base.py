from typing import Union
from uuid import UUID

from tortoise.fields.data import CharField, TextField, UUIDField
from tortoise.models import Model

from app.models.mixin import CountMixin, DeleteMixin


class AbstractBaseModel(Model, DeleteMixin, CountMixin):
    id = UUIDField(pk=True)

    class Meta:
        abstract = True


class AbstractResourceModel(Model, DeleteMixin, CountMixin):
    id = CharField(max_length=64, pk=True)
    content = TextField()

    class Meta:
        abstract = True

    @classmethod
    async def get_by_id(cls, id_: Union[str, UUID]) -> "AbstractResourceModel":
        return await cls.get(id=str(id_))
