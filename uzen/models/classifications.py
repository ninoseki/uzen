from tortoise import fields

from uzen.models.base import AbstractBaseModel
from uzen.models.mixins import TimestampMixin
from uzen.schemas.classifications import Classification as ClassificationModel


class Classification(TimestampMixin, AbstractBaseModel):
    name = fields.CharField(max_length=100)
    malicious = fields.BooleanField()
    note = fields.TextField(null=True)

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot",
        related_name="_classifications",
        to_field="id",
        on_delete=fields.CASCADE,
    )

    def to_model(self) -> ClassificationModel:
        return ClassificationModel.from_orm(self)

    class Meta:
        table = "classifications"
