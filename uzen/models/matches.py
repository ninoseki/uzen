from tortoise import fields
from tortoise.models import Model

from uzen.schemas.matches import Match as MatchModel


class Match(Model):
    id = fields.IntField(pk=True)
    matches = fields.JSONField()
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot"
    )
    rule: fields.ForeignKeyRelation["Rule"] = fields.ForeignKeyField("models.Rule")
    script: fields.ForeignKeyNullableRelation["Script"] = fields.ForeignKeyField(
        "models.Script", null=True
    )

    def to_model(self) -> MatchModel:
        return MatchModel.from_orm(self)

    class Meta:
        table = "matches"
        ordering = ["-id"]
