from typing import TYPE_CHECKING

from tortoise.fields.base import CASCADE
from tortoise.fields.data import CharField, TextField
from tortoise.fields.relational import ForeignKeyField, ForeignKeyRelation

from app import schemas

from .base import AbstractBaseModel
from .mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models.snapshot import Snapshot


class DnsRecord(TimestampMixin, AbstractBaseModel):
    type = CharField(max_length=5)
    value = TextField()

    snapshot: ForeignKeyRelation["Snapshot"] = ForeignKeyField(
        "models.Snapshot",
        related_name="_dns_records",
        to_field="id",
        on_delete=CASCADE,
    )

    def to_model(self) -> schemas.DnsRecord:
        return schemas.DnsRecord.from_orm(self)

    class Meta:
        table = "dns_records"
        ordering = ["type"]
