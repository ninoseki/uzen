from typing import TYPE_CHECKING

from tortoise.fields.base import CASCADE
from tortoise.fields.data import JSONField
from tortoise.fields.relational import (
    ForeignKeyField,
    ForeignKeyNullableRelation,
    ForeignKeyRelation,
)

from app import schemas
from app.factories.match import MatchFactory

from .base import AbstractBaseModel
from .mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models import Rule, Script, Snapshot


class Match(TimestampMixin, AbstractBaseModel):
    matches = JSONField()

    snapshot: ForeignKeyRelation["Snapshot"] = ForeignKeyField(
        "models.Snapshot", on_delete=CASCADE
    )
    rule: ForeignKeyRelation["Rule"] = ForeignKeyField("models.Rule", on_delete=CASCADE)
    script: ForeignKeyNullableRelation["Script"] = ForeignKeyField(
        "models.Script", null=True, on_delete=CASCADE
    )

    def to_model(self) -> schemas.Match:
        return MatchFactory.from_model(self)

    class Meta:
        table = "matches"
        ordering = ["-created_at"]
