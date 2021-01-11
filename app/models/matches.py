from tortoise import fields

from app.models.base import AbstractBaseModel
from app.models.mixins import TimestampMixin
from app.schemas.matches import Match as MatchModel


class Match(TimestampMixin, AbstractBaseModel):
    matches = fields.JSONField()

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot", on_delete=fields.CASCADE
    )
    rule: fields.ForeignKeyRelation["Rule"] = fields.ForeignKeyField(
        "models.Rule", on_delete=fields.CASCADE
    )
    script: fields.ForeignKeyNullableRelation["Script"] = fields.ForeignKeyField(
        "models.Script", null=True, on_delete=fields.CASCADE
    )

    def to_model(self) -> MatchModel:
        return MatchModel.from_orm(self)

    class Meta:
        table = "matches"
        ordering = ["-created_at"]
