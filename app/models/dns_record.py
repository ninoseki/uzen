from tortoise import fields

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin


class DnsRecord(TimestampMixin, AbstractBaseModel):
    type = fields.CharField(max_length=5)
    value = fields.TextField()

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot",
        related_name="_dns_records",
        to_field="id",
        on_delete=fields.CASCADE,
    )

    def to_model(self) -> schemas.DnsRecord:
        return schemas.DnsRecord.from_orm(self)

    class Meta:
        table = "dns_records"
