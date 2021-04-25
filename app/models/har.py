from typing import TYPE_CHECKING
from uuid import UUID

from tortoise.fields.base import CASCADE
from tortoise.fields.data import UUIDField
from tortoise.fields.relational import OneToOneField, OneToOneRelation
from tortoise.models import Model

from app import schemas
from app.database.fields import CustomJSONField
from app.models.mixin import CountMixin, DeleteMixin, TimestampMixin

if TYPE_CHECKING:
    from app.models import Snapshot


class HAR(Model, TimestampMixin, CountMixin, DeleteMixin):
    id = UUIDField(pk=True)

    data = CustomJSONField()

    snapshot: OneToOneRelation["Snapshot"] = OneToOneField(
        "models.Snapshot", related_name="har", on_delete=CASCADE
    )

    def to_model(self) -> schemas.HAR:
        return schemas.HAR.from_orm(self)

    @classmethod
    async def get_by_snapshot_id(cls, id_: UUID) -> "HAR":
        return await cls.get(snapshot_id=id_)

    class Meta:
        table = "hars"
