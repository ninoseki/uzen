from typing import TYPE_CHECKING

from tortoise.fields.base import CASCADE
from tortoise.fields.data import BooleanField, CharField, TextField
from tortoise.fields.relational import ForeignKeyField, ForeignKeyRelation

from app import schemas

from .base import AbstractBaseModel
from .mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models import Snapshot


class Classification(TimestampMixin, AbstractBaseModel):
    name = CharField(max_length=100)
    malicious = BooleanField()
    note = TextField(null=True)

    snapshot: ForeignKeyRelation["Snapshot"] = ForeignKeyField(
        "models.Snapshot",
        related_name="_classifications",
        to_field="id",
        on_delete=CASCADE,
    )

    def to_model(self) -> schemas.Classification:
        return schemas.Classification.from_orm(self)

    class Meta:
        table = "classifications"
