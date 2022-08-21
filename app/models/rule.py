from __future__ import annotations

from typing import Any

from tortoise.fields.data import CharField, DatetimeField, TextField
from tortoise.fields.relational import ManyToManyRelation

from app import models, schemas, types
from app.factories.rule import RuleFactory

from .base import AbstractBaseModel
from .mixin import TimestampMixin

LIMIT_OF_PREFETCH = 20


class Rule(TimestampMixin, AbstractBaseModel):
    name = CharField(max_length=255, unique=True)
    target = CharField(max_length=255)
    source = TextField()

    allowed_network_addresses = TextField(null=True)
    disallowed_network_addresses = TextField(null=True)
    allowed_resource_hashes = TextField(null=True)
    disallowed_resource_hashes = TextField(null=True)

    updated_at = DatetimeField(auto_now=True)

    snapshots: ManyToManyRelation[models.Snapshot]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

        self.related_snapshots: list[models.Snapshot] | None = None

    def to_model(self) -> schemas.Rule:
        return RuleFactory.from_model(self)

    @classmethod
    async def get_by_id(cls, id_: str | types.ULID) -> Rule:
        rule = await cls.get(id=str(id_))
        rule.related_snapshots = (
            await rule.snapshots.all()
            .limit(LIMIT_OF_PREFETCH)
            .prefetch_related(
                "html",
                "whois",
                "certificate",
            )
        )

        return rule

    class Meta:
        table = "rules"
        ordering = ["-created_at"]
