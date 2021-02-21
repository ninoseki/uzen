from __future__ import annotations

from typing import Any, List, cast
from uuid import UUID

from tortoise.fields.data import CharField, DatetimeField, TextField
from tortoise.fields.relational import ManyToManyRelation

from app import models, schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin

LIMIT_OF_PREFETCH = 20


class Rule(TimestampMixin, AbstractBaseModel):
    name = CharField(max_length=255)
    target = CharField(max_length=255)
    source = TextField()
    updated_at = DatetimeField(auto_now=True)

    _snapshots: ManyToManyRelation[models.Snapshot]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

        self.snapshots_: list[models.Snapshot] | None = None

    @property
    def snapshots(self) -> list[schemas.Snapshot]:
        if hasattr(self, "snapshots_") and self.snapshots_ is not None:
            return cast(
                List[schemas.Snapshot],
                [snapshot.to_model() for snapshot in self.snapshots_],
            )

        return []

    def to_model(self) -> schemas.Rule:
        return schemas.Rule.from_orm(self)

    @classmethod
    async def get_by_id(cls, id_: str | UUID) -> Rule:
        rule = await cls.get(id=str(id_))
        rule.snapshots_ = (
            await rule._snapshots.all()
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
