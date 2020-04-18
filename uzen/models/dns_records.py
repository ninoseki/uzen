from typing import Union

from tortoise import fields

from uzen.models.base import AbstractBaseModel
from uzen.models.mixins import TimestampMixin
from uzen.schemas.dns_records import BaseDnsRecord
from uzen.schemas.dns_records import DnsRecord as DnsRecordModel


class DnsRecord(TimestampMixin, AbstractBaseModel):
    type = fields.CharField(max_length=5)
    value = fields.TextField()

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot",
        related_name="_dns_records",
        to_field="id",
        on_delete=fields.CASCADE,
    )

    def to_model(self) -> Union[DnsRecordModel, BaseDnsRecord]:
        if self.created_at is not None:
            return DnsRecordModel.from_orm(self)

        return BaseDnsRecord.from_orm(self)

    class Meta:
        table = "dns_records"
