from tortoise import fields
from tortoise.models import Model

from uzen.schemas.rules import Rule as RuleModel


class Rule(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=255)
    target = fields.CharField(max_length=255)
    source = fields.TextField()
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshots: fields.ManyToManyRelation["Snapshot"]

    def to_model(self) -> RuleModel:
        return RuleModel.from_orm(self)

    class Meta:
        table = "rules"
        ordering = ["-id"]
