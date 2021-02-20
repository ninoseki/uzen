from __future__ import annotations

from typing import Any, List, cast
from uuid import UUID

from tortoise import fields

from app import models, schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin

LIMIT_OF_PREFETCH = 20


class Rule(TimestampMixin, AbstractBaseModel):
    name = fields.CharField(max_length=255)
    target = fields.CharField(max_length=255)
    source = fields.TextField()
    updated_at = fields.DatetimeField(auto_now=True)

    _snapshots: fields.ManyToManyRelation[models.Snapshot]

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
    async def get_by_id(cls, id_: UUID) -> Rule:
        rule = await cls.get(id=id_)
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
