from __future__ import annotations

from typing import List
from uuid import UUID

from tortoise import fields
from tortoise.exceptions import NoValuesFetched

from app.models.base import AbstractBaseModel
from app.models.mixins import TimestampMixin
from app.schemas.classifications import Classification
from app.schemas.dns_records import DnsRecord
from app.schemas.rules import Rule
from app.schemas.scripts import Script
from app.schemas.snapshots import Snapshot as SnapshotModel


class Snapshot(TimestampMixin, AbstractBaseModel):
    """An ORM class for snapshots table"""

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
    whois = fields.TextField(null=True)
    certificate = fields.TextField(null=True)
    request = fields.JSONField()
    processing = fields.BooleanField(default=True)

    _scripts: fields.ReverseRelation["Script"]
    _dns_records: fields.ReverseRelation["DnsRecord"]
    _classifications: fields.ReverseRelation["Classification"]

    _rules: fields.ManyToManyRelation["Rule"] = fields.ManyToManyField(
        "models.Rule",
        related_name="_snapshots",
        through="matches",
        forward_key="rule_id",
        backward_key="snapshot_id",
    )

    @property
    def rules(self) -> List[Rule]:
        try:
            return [rule.to_model() for rule in self._rules]
        except NoValuesFetched:
            return []

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

    def to_model(self) -> SnapshotModel:
        return SnapshotModel.from_orm(self)

    def to_dict(self) -> dict:
        model = self.to_model()
        return model.dict()

    @classmethod
    async def get_by_id(cls, id_: UUID) -> Snapshot:
        return await cls.get(id=id_).prefetch_related(
            "_scripts__file", "_dns_records", "_classifications", "_rules"
        )

    @classmethod
    async def find_by_ip_address(cls, ip_address: str, size=20) -> List[Snapshot]:
        return await cls.filter(ip_address=ip_address).limit(size)

    @classmethod
    async def find_by_hostname(cls, hostname: str, size=20) -> List[Snapshot]:
        return await cls.filter(hostname=hostname).limit(size)

    class Meta:
        table = "snapshots"
        ordering = ["-created_at"]
