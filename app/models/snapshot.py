from __future__ import annotations

from typing import TYPE_CHECKING, List
from uuid import UUID

from tortoise import fields, models
from tortoise.exceptions import IntegrityError, NoValuesFetched
from tortoise.transactions import in_transaction

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin
from app.models.script import Script
from app.models.stylesheet import Stylesheet

if TYPE_CHECKING:
    from app.dataclasses import SnapshotResult


async def save_ignore_integrity_error(model: models):
    try:
        await model.save()
    except IntegrityError:
        # ignore the intergrity error
        # e.g. tortoise.exceptions.IntegrityError: UNIQUE constraint failed: files.id
        pass


class Snapshot(TimestampMixin, AbstractBaseModel):
    """An ORM class for snapshots table"""

    url = fields.TextField()
    submitted_url = fields.TextField()
    status = fields.IntField()
    hostname = fields.TextField()
    ip_address = fields.CharField(max_length=255)
    asn = fields.TextField()
    country_code = fields.CharField(max_length=2)
    response_headers = fields.JSONField()
    request_headers = fields.JSONField()
    ignore_https_errors = fields.BooleanField(default=False)
    processing = fields.BooleanField(default=True)

    html: fields.ForeignKeyRelation["HTML"] = fields.ForeignKeyField(  # noqa F821
        "models.HTML", related_name="snapshots", on_delete=fields.RESTRICT
    )
    certificate: fields.ForeignKeyNullableRelation[
        "Certificate"  # noqa F821
    ] = fields.ForeignKeyField(
        "models.Certificate",
        related_name="snapshots",
        on_delete=fields.RESTRICT,
        null=True,
    )
    whois: fields.ForeignKeyNullableRelation[
        "Whois"  # noqa F821
    ] = fields.ForeignKeyField(
        "models.Whois", related_name="snapshots", on_delete=fields.RESTRICT, null=True
    )

    har = fields.OneToOneRelation["HAR"]

    _scripts: fields.ReverseRelation["Script"]
    _stylesheets: fields.ReverseRelation["Stylesheet"]
    _dns_records: fields.ReverseRelation["DnsRecord"]  # noqa F821
    _classifications: fields.ReverseRelation["Classification"]  # noqa F821

    _rules: fields.ManyToManyRelation["Rule"] = fields.ManyToManyField(  # noqa F821
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
    def stylesheets(self) -> List[schemas.Stylesheet]:
        try:
            return [stylesheet.to_model() for stylesheet in self._stylesheets]
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
            "_stylesheets__file",
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

    @classmethod
    async def save_snapshot_result(_, result: "SnapshotResult",) -> Snapshot:
        async with in_transaction():
            snapshot = result.snapshot

            # save html, certificate, whois before saving snapshot
            html = result.html
            await save_ignore_integrity_error(html)
            snapshot.html_id = html.id

            certificate = result.certificate
            if certificate:
                await save_ignore_integrity_error(certificate)
                snapshot.certificate_id = certificate.id

            whois = result.whois
            if whois:
                await save_ignore_integrity_error(whois)
                snapshot.whois_id = whois.id

            # save snapshot
            await snapshot.save()

            # save scripts
            await Script.save_script_files(result.script_files, snapshot.id)

            # save stylesheets
            await Stylesheet.save_stylesheet_files(result.stylesheet_files, snapshot.id)

            # save har
            har = result.har
            if har:
                har.snapshot_id = snapshot.id
                await har.save()

            return snapshot

    class Meta:
        table = "snapshots"
        ordering = ["-created_at"]
