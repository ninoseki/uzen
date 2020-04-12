from typing import TYPE_CHECKING, List

from tortoise import fields
from tortoise.exceptions import NoValuesFetched
from tortoise.models import Model

from uzen.schemas.rules import Rule as RuleModel

if TYPE_CHECKING:
    from uzen.schemas.snapshots import Snapshot  # noqa


class Rule(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=255)
    target = fields.CharField(max_length=255)
    source = fields.TextField()
    created_at = fields.DatetimeField(auto_now_add=True)

    _snapshots: fields.ManyToManyRelation["Snapshot"]

    @property
    def snapshots(self) -> List["Snapshot"]:
        try:
            return [snapshot.to_model() for snapshot in self._snapshots]
        except NoValuesFetched:
            return []

    def to_model(self) -> RuleModel:
        return RuleModel.from_orm(self)

    class Meta:
        table = "rules"
        ordering = ["-id"]
