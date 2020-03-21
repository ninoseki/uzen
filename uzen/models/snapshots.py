from tortoise import fields
from tortoise.models import Model
from typing import Union

from uzen.models.schemas.snapshots import BaseSnapshot, Snapshot as SnapshotModel


class Snapshot(Model):
    """An ORM class for snapshots table"""

    id = fields.IntField(pk=True)
    url = fields.TextField()
    submitted_url = fields.TextField()
    status = fields.IntField()
    hostname = fields.TextField()
    ip_address = fields.CharField(max_length=255)
    asn = fields.TextField()
    server = fields.TextField(null=True)
    content_type = fields.TextField(null=True)
    content_length = fields.IntField(null=True)
    body = fields.TextField()
    sha256 = fields.CharField(max_length=64)
    headers = fields.JSONField()
    screenshot = fields.TextField()
    whois = fields.TextField(null=True)
    certificate = fields.TextField(null=True)
    request = fields.JSONField()
    created_at = fields.DatetimeField(auto_now_add=True)

    scripts: fields.ReverseRelation["Script"]
    dns_records: fields.ReverseRelation["DnsRecord"]

    def to_model(self) -> Union[BaseSnapshot, SnapshotModel]:
        if self.id is not None:
            return SnapshotModel.from_orm(self)

        return BaseSnapshot.from_orm(self)

    def to_dict(self) -> dict:
        model = self.to_model()
        return model.dict()

    class Meta:
        table = "snapshots"
