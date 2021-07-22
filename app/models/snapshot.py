from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from tortoise.exceptions import IntegrityError, NoValuesFetched
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

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin
from app.models.script import Script
from app.models.stylesheet import Stylesheet
from app.models.tag import Tag

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
    api_key: ForeignKeyNullableRelation[APIKey] = ForeignKeyField(
        "models.APIKey", related_name="snapshots", on_delete=RESTRICT, null=True
    )

    har = OneToOneRelation["HAR"]

    _scripts: ReverseRelation[Script]
    _stylesheets: ReverseRelation[Stylesheet]
    _dns_records: ReverseRelation[DnsRecord]
    _classifications: ReverseRelation[Classification]

    _rules: ManyToManyRelation[Rule] = ManyToManyField(
        "models.Rule",
        related_name="_snapshots",
        through="matches",
        forward_key="rule_id",
        backward_key="snapshot_id",
    )

    _tags: ManyToManyRelation[Tag] = ManyToManyField(
        "models.Tag",
        related_name="_snapshots",
        through="taggings",
        forward_key="tag_id",
        backward_key="snapshot_id",
    )

    @property
    def rules(self) -> list[schemas.Rule]:
        try:
            return [rule.to_model() for rule in self._rules]
        except NoValuesFetched:
            return []

    @property
    def tags(self) -> list[schemas.Tag]:
        try:
            return [tag.to_model() for tag in self._tags]
        except NoValuesFetched:
            return []

    @property
    def scripts(self) -> list[schemas.Script]:
        try:
            return [script.to_model() for script in self._scripts]
        except NoValuesFetched:
            return []

    @property
    def stylesheets(self) -> list[schemas.Stylesheet]:
        try:
            return [stylesheet.to_model() for stylesheet in self._stylesheets]
        except NoValuesFetched:
            return []

    @property
    def dns_records(self) -> list[schemas.DnsRecord]:
        try:
            return [record.to_model() for record in self._dns_records]
        except NoValuesFetched:
            return []

    @property
    def classifications(self) -> list[schemas.Classification]:
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
    async def get_by_id(cls, id_: str | UUID) -> Snapshot:
        return await cls.get(id=str(id_)).prefetch_related(
            "_scripts",
            "_stylesheets",
            "_dns_records",
            "_classifications",
            "_rules",
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
                await snapshot._tags.add(*tags_)

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
