from __future__ import annotations

from typing import Any, List, Optional, cast
from uuid import UUID

from tortoise import fields

from app.models.base import AbstractBaseModel
from app.models.mixins import TimestampMixin
from app.models.snapshots import Snapshot
from app.schemas.rules import Rule as RuleModel
from app.schemas.snapshots import Snapshot as SnapshotModel

LIMIT_OF_PREFETCH = 20


class Rule(TimestampMixin, AbstractBaseModel):
    name = fields.CharField(max_length=255)
    target = fields.CharField(max_length=255)
    source = fields.TextField()
    updated_at = fields.DatetimeField(auto_now=True)

    _snapshots: fields.ManyToManyRelation[Snapshot]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

        self.snapshots_: Optional[List[Snapshot]] = None

    @property
    def snapshots(self) -> List[SnapshotModel]:
        if hasattr(self, "snapshots_") and self.snapshots_ is not None:
            return cast(
                List[SnapshotModel],
                [snapshot.to_model() for snapshot in self.snapshots_],
            )

        return []

    def to_model(self) -> RuleModel:
        return RuleModel.from_orm(self)

    @classmethod
    async def get_by_id(cls, id_: UUID) -> Rule:
        rule = await cls.get(id=id_)
        rule.snapshots_ = await rule._snapshots.all().limit(LIMIT_OF_PREFETCH)
        return rule

    class Meta:
        table = "rules"
        ordering = ["-created_at"]
