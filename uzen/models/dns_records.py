from tortoise import fields
from tortoise.models import Model
from pydantic import AnyHttpUrl, BaseModel
import datetime


from uzen.models.snapshots import Snapshot


class DnsRecordBaseModel(BaseModel):
    """Base Pydantic model for DnsRecord

    Note that this model doesn't have "id" and "created_at" fields.
    """

    type: str
    value: str

    class Config:
        orm_mode = True


class DnsRecordModel(DnsRecordBaseModel):
    """Full Pydantic model for DnsRecord

    """

    id: int
    created_at: datetime.datetime


class DnsRecord(Model):
    id = fields.IntField(pk=True)
    type = fields.CharField(max_length=5)
    value = fields.TextField()
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshot: fields.ForeignKeyRelation[Snapshot] = fields.ForeignKeyField(
        "models.Snapshot", related_name="dns_records", to_field="id"
    )

    def to_full_model(self) -> DnsRecordModel:
        return DnsRecordModel.from_orm(self)

    class Meta:
        table = "dns_records"
