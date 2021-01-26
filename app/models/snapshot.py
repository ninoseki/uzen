from __future__ import annotations

from typing import List
from uuid import UUID

from tortoise import fields
from tortoise.exceptions import NoValuesFetched

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin


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
    headers = fields.JSONField()
    options = fields.JSONField()
    processing = fields.BooleanField(default=True)

    html: fields.ForeignKeyRelation["HTML"] = fields.ForeignKeyField(
        "models.HTML", related_name="snapshots", on_delete=fields.RESTRICT
    )
    certificate: fields.ForeignKeyNullableRelation[
        "Certificate"
    ] = fields.ForeignKeyField(
        "models.Certificate",
        related_name="snapshots",
        on_delete=fields.RESTRICT,
        null=True,
    )
    whois: fields.ForeignKeyNullableRelation["Whois"] = fields.ForeignKeyField(
        "models.Whois", related_name="snapshots", on_delete=fields.RESTRICT, null=True
    )

    har = fields.OneToOneRelation["HAR"]

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
    def rules(self) -> List[schemas.Rule]:
        try:
            return [rule.to_model() for rule in self._rules]
        except NoValuesFetched:
            return []

    @property
    def scripts(self) -> List[schemas.Script]:
        try:
            return [script.to_model() for script in self._scripts]
        except NoValuesFetched:
            return []

    @property
    def dns_records(self) -> List[schemas.DnsRecord]:
        try:
            return [record.to_model() for record in self._dns_records]
        except NoValuesFetched:
            return []

    @property
    def classifications(self) -> List[schemas.Classification]:
        try:
            return [
                classification.to_model() for classification in self._classifications
            ]
        except NoValuesFetched:
            return []

    def to_model(self) -> schemas.Snapshot:
        return schemas.Snapshot.from_orm(self)

    def to_plain_model(self) -> schemas.PlainSnapshot:
        return schemas.PlainSnapshot.from_orm(self)

    def to_dict(self) -> dict:
        model = self.to_model()
        return model.dict()

    @classmethod
    async def get_by_id(cls, id_: UUID) -> Snapshot:
        return await cls.get(id=id_).prefetch_related(
            "_scripts__file",
            "_dns_records",
            "_classifications",
            "_rules",
            "html",
            "whois",
            "certificate",
        )

    @classmethod
    async def find_by_ip_address(cls, ip_address: str, size=20) -> List[Snapshot]:
        return (
            await cls.filter(ip_address=ip_address)
            .limit(size)
            .prefetch_related("html", "whois", "certificate",)
        )

    @classmethod
    async def find_by_hostname(cls, hostname: str, size=20) -> List[Snapshot]:
        return (
            await cls.filter(hostname=hostname)
            .limit(size)
            .prefetch_related("html", "whois", "certificate",)
        )

    class Meta:
        table = "snapshots"
        ordering = ["-created_at"]
