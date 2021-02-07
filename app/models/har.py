from uuid import UUID

from tortoise import fields
from tortoise.models import Model

from app import schemas
from app.models.mixin import CountMixin, DeleteMixin, TimestampMixin


class HAR(Model, TimestampMixin, CountMixin, DeleteMixin):
    id = fields.UUIDField(pk=True)

    data = fields.JSONField()

    snapshot: fields.OneToOneRelation["Snapshot"] = fields.OneToOneField(  # noqa F821
        "models.Snapshot", related_name="har", on_delete=fields.CASCADE
    )

    def to_model(self) -> schemas.HAR:
        return schemas.HAR.from_orm(self)

    @classmethod
    async def get_by_snapshot_id(cls, id_: UUID) -> "HAR":
        return await cls.get(snapshot_id=id_)

    class Meta:
        table = "hars"
