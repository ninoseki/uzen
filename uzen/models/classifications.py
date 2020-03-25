from tortoise import fields
from tortoise.models import Model

from uzen.models.snapshots import Snapshot
from uzen.models.schemas.classifications import Classification as ClassificationModel


class Classification(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=100)
    malicious = fields.BooleanField()
    note = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshot: fields.ForeignKeyRelation[Snapshot] = fields.ForeignKeyField(
        "models.Snapshot", related_name="classifications", to_field="id"
    )

    def to_model(self) -> ClassificationModel:
        return ClassificationModel.from_orm(self)

    class Meta:
        table = "classifications"
