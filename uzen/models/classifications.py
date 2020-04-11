from typing import Union

from tortoise import fields
from tortoise.models import Model

from uzen.schemas.classifications import BaseClassification
from uzen.schemas.classifications import Classification as ClassificationModel


class Classification(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=100)
    malicious = fields.BooleanField()
    note = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot", related_name="_classifications", to_field="id"
    )

    def to_model(self) -> Union[ClassificationModel, BaseClassification]:
        if self.id is not None:
            return ClassificationModel.from_orm(self)

        return BaseClassification.from_orm(self)

    class Meta:
        table = "classifications"
