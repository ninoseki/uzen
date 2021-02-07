from tortoise import fields

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin


class Classification(TimestampMixin, AbstractBaseModel):
    name = fields.CharField(max_length=100)
    malicious = fields.BooleanField()
    note = fields.TextField(null=True)

    snapshot: fields.ForeignKeyRelation[
        "Snapshot"  # noqa F821
    ] = fields.ForeignKeyField(
        "models.Snapshot",
        related_name="_classifications",
        to_field="id",
        on_delete=fields.CASCADE,
    )

    def to_model(self) -> schemas.Classification:
        return schemas.Classification.from_orm(self)

    class Meta:
        table = "classifications"
