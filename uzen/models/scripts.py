from typing import Union

from tortoise import fields

from uzen.models.base import AbstractBaseModel
from uzen.models.mixins import TimestampMixin
from uzen.schemas.scripts import BaseScript
from uzen.schemas.scripts import Script as ScriptModel


class Script(TimestampMixin, AbstractBaseModel):
    url = fields.TextField()
    content = fields.TextField()
    sha256 = fields.CharField(max_length=64)

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot",
        related_name="_scripts",
        to_field="id",
        on_delete=fields.CASCADE,
    )

    def to_model(self) -> Union[ScriptModel, BaseScript]:
        if self.created_at is not None:
            return ScriptModel.from_orm(self)

        return BaseScript.from_orm(self)

    class Meta:
        table = "scripts"
