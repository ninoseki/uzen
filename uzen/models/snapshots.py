from tortoise import fields
from tortoise.exceptions import NoValuesFetched
from tortoise.models import Model
from typing import Union, List

from uzen.models.schemas.classifications import Classification
from uzen.models.schemas.dns_records import DnsRecord
from uzen.models.schemas.scripts import Script
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

    _scripts: fields.ReverseRelation["Script"]
    _dns_records: fields.ReverseRelation["DnsRecord"]
    _classifications: fields.ReverseRelation["Classification"]

    @property
    def scripts(self) -> List[Script]:
        try:
            return [script.to_model() for script in self._scripts]
        except NoValuesFetched:
            return []

    @property
    def dns_records(self) -> List[DnsRecord]:
        try:
            return [record.to_model() for record in self._dns_records]
        except NoValuesFetched:
            return []

    @property
    def classifications(self) -> List[Classification]:
        try:
            return [
                classification.to_model() for classification in self._classifications
            ]
        except NoValuesFetched:
            return []

    def to_model(self) -> Union[BaseSnapshot, SnapshotModel]:
        if self.id is not None:
            return SnapshotModel.from_orm(self)

        return BaseSnapshot.from_orm(self)

    def to_dict(self) -> dict:
        model = self.to_model()
        return model.dict()

    class Meta:
        table = "snapshots"
