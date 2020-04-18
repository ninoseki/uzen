from __future__ import annotations

from typing import TYPE_CHECKING, List

from tortoise import fields
from tortoise.exceptions import NoValuesFetched

from uzen.models.base import AbstractBaseModel
from uzen.models.mixins import TimestampMixin
from uzen.schemas.rules import Rule as RuleModel

if TYPE_CHECKING:
    from uzen.schemas.snapshots import Snapshot  # noqa


class Rule(TimestampMixin, AbstractBaseModel):
    name = fields.CharField(max_length=255)
    target = fields.CharField(max_length=255)
    source = fields.TextField()
    updated_at = fields.DatetimeField(auto_now=True)

    _snapshots: fields.ManyToManyRelation["Snapshot"]

    @property
    def snapshots(self) -> List["Snapshot"]:
        try:
            return [snapshot.to_model() for snapshot in self._snapshots]
        except NoValuesFetched:
            return []

    def to_model(self) -> RuleModel:
        return RuleModel.from_orm(self)

    @classmethod
    async def get_by_id(cls, id_: int) -> Rule:
        return await cls.get(id=id_).prefetch_related("_snapshots")

    class Meta:
        table = "rules"
        ordering = ["-id"]
