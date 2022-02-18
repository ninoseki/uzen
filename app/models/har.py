from typing import TYPE_CHECKING

from tortoise.fields.base import CASCADE
from tortoise.fields.data import JSONField
from tortoise.fields.relational import OneToOneField, OneToOneRelation
from tortoise.models import Model

from app import schemas, types

from .fields import ULIDField
from .mixin import CountMixin, DeleteMixin, TimestampMixin

if TYPE_CHECKING:
    from app.models import Snapshot


class HAR(Model, TimestampMixin, CountMixin, DeleteMixin):
    id = ULIDField(pk=True)

    data = JSONField()

    snapshot: OneToOneRelation["Snapshot"] = OneToOneField(
        "models.Snapshot", related_name="har", on_delete=CASCADE
    )

    def to_model(self) -> schemas.HAR:
        return schemas.HAR.from_orm(self)

    @classmethod
    async def get_by_snapshot_id(cls, id_: types.ULID) -> "HAR":
        return await cls.get(snapshot_id=id_)

    class Meta:
        table = "hars"
