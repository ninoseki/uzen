from tortoise import fields

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin


class Match(TimestampMixin, AbstractBaseModel):
    matches = fields.JSONField()

    snapshot: fields.ForeignKeyRelation[
        "Snapshot"  # noqa F821
    ] = fields.ForeignKeyField("models.Snapshot", on_delete=fields.CASCADE)
    rule: fields.ForeignKeyRelation["Rule"] = fields.ForeignKeyField(  # noqa F821
        "models.Rule", on_delete=fields.CASCADE
    )
    script: fields.ForeignKeyNullableRelation[
        "Script"  # noqa F821
    ] = fields.ForeignKeyField("models.Script", null=True, on_delete=fields.CASCADE)

    def to_model(self) -> schemas.Match:
        return schemas.Match.from_orm(self)

    class Meta:
        table = "matches"
        ordering = ["-created_at"]
