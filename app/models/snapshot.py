from __future__ import annotations

from typing import TYPE_CHECKING

from tortoise.exceptions import IntegrityError
from tortoise.fields.base import RESTRICT
from tortoise.fields.data import BooleanField, CharField, IntField, JSONField, TextField
from tortoise.fields.relational import (
    ForeignKeyField,
    ForeignKeyNullableRelation,
    ForeignKeyRelation,
    ManyToManyField,
    ManyToManyRelation,
    OneToOneRelation,
    ReverseRelation,
)
from tortoise.transactions import in_transaction

from app import schemas, types
from app.builders.snapshot import SnapshotBuilder
from app.models.script import Script
from app.models.stylesheet import Stylesheet
from app.models.tag import Tag

from .base import AbstractBaseModel
from .mixin import TimestampMixin

if TYPE_CHECKING:
    from app.dataclasses import SnapshotModelWrapper
    from app.models import (
        HTML,
        APIKey,
        Certificate,
        Classification,
        DnsRecord,
        Rule,
        Whois,
    )


async def save_ignore_integrity_error(model: "HTML" | "Certificate" | "Whois") -> None:
    try:
        await model.save()
    except IntegrityError:
        # ignore the integrity error
        # e.g. tortoise.exceptions.IntegrityError: UNIQUE constraint failed: files.id
        pass


class Snapshot(TimestampMixin, AbstractBaseModel):
    """An ORM class for snapshots table"""

    url = TextField()
    submitted_url = TextField()
    status = IntField()
    hostname = TextField()
    ip_address = CharField(max_length=255)
    asn = CharField(max_length=255)
    country_code = CharField(max_length=2)
    response_headers = JSONField()
    request_headers = JSONField()
    ignore_https_errors = BooleanField(default=False)
    processing = BooleanField(default=True)

    api_key: ForeignKeyRelation[APIKey] = ForeignKeyField(
        "models.APIKey", related_name="snapshots", on_delete=RESTRICT
    )
    html: ForeignKeyRelation[HTML] = ForeignKeyField(
        "models.HTML", related_name="snapshots", on_delete=RESTRICT
    )

    certificate: ForeignKeyNullableRelation[Certificate] = ForeignKeyField(
        "models.Certificate",
        related_name="snapshots",
        on_delete=RESTRICT,
        null=True,
    )
    whois: ForeignKeyNullableRelation[Whois] = ForeignKeyField(
        "models.Whois", related_name="snapshots", on_delete=RESTRICT, null=True
    )

    har = OneToOneRelation["HAR"]

    scripts: ReverseRelation[Script]
    stylesheets: ReverseRelation[Stylesheet]
    dns_records: ReverseRelation[DnsRecord]
    classifications: ReverseRelation[Classification]

    rules: ManyToManyRelation[Rule] = ManyToManyField(
        "models.Rule",
        related_name="snapshots",
        through="matches",
        forward_key="rule_id",
        backward_key="snapshot_id",
    )

    tags: ManyToManyRelation[Tag] = ManyToManyField(
        "models.Tag",
        related_name="snapshots",
        through="taggings",
        forward_key="tag_id",
        backward_key="snapshot_id",
    )

    def to_model(self) -> schemas.Snapshot:
        return SnapshotBuilder.build(self)

    def to_plain_model(self) -> schemas.PlainSnapshot:
        return schemas.PlainSnapshot.from_orm(self)

    @classmethod
    async def get_by_id(cls, id_: str | types.ULID) -> Snapshot:
        return await cls.get(id=str(id_)).prefetch_related(
            "scripts",
            "stylesheets",
            "dns_records",
            "classifications",
            "rules",
            "tags",
            "html",
            "whois",
            "certificate",
        )

    @classmethod
    async def find_by_ip_address(
        cls, ip_address: str, size: int = 20
    ) -> list[Snapshot]:
        return (
            await cls.filter(ip_address=ip_address)
            .limit(size)
            .prefetch_related(
                "html",
                "whois",
                "certificate",
            )
        )

    @classmethod
    async def find_by_hostname(cls, hostname: str, size: int = 20) -> list[Snapshot]:
        return (
            await cls.filter(hostname=hostname)
            .limit(size)
            .prefetch_related(
                "html",
                "whois",
                "certificate",
            )
        )

    @classmethod
    async def save_snapshot(
        _cls,
        wrapper: "SnapshotModelWrapper",
        *,
        id: str | None = None,
        api_key: str | None = None,
        tag_names: list[str] | None = None,
    ) -> Snapshot:
        async with in_transaction():
            snapshot = wrapper.snapshot

            if id is not None:
                snapshot.id = id

            # save html, certificate, whois before saving snapshot
            html = wrapper.html
            await save_ignore_integrity_error(html)
            snapshot.html_id = html.id

            certificate = wrapper.certificate
            if certificate:
                await save_ignore_integrity_error(certificate)
                snapshot.certificate_id = certificate.id

            whois = wrapper.whois
            if whois:
                await save_ignore_integrity_error(whois)
                snapshot.whois_id = whois.id

            if api_key:
                snapshot.api_key_id = api_key

            # save snapshot
            await snapshot.save()

            # create and add tags
            if tag_names:
                tags_ = [(await Tag.get_or_create(name=name))[0] for name in tag_names]
                await snapshot.tags.add(*tags_)

            # save scripts
            await Script.save_script_files(wrapper.script_files, snapshot.id)

            # save stylesheets
            await Stylesheet.save_stylesheet_files(
                wrapper.stylesheet_files, snapshot.id
            )

            # save har
            har = wrapper.har
            if har:
                har.snapshot_id = snapshot.id
                await har.save()

            return snapshot

    class Meta:
        table = "snapshots"
        ordering = ["-created_at"]
