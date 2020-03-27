from typing import Union

from tortoise import fields
from tortoise.models import Model

from uzen.models.schemas.dns_records import BaseDnsRecord
from uzen.models.schemas.dns_records import DnsRecord as DnsRecordModel


class DnsRecord(Model):
    id = fields.IntField(pk=True)
    type = fields.CharField(max_length=5)
    value = fields.TextField()
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot", related_name="_dns_records", to_field="id"
    )

    def to_model(self) -> Union[DnsRecordModel, BaseDnsRecord]:
        if self.id is not None:
            return DnsRecordModel.from_orm(self)

        return BaseDnsRecord.from_orm(self)

    class Meta:
        table = "dns_records"
