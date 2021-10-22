from typing import TYPE_CHECKING

from tortoise.fields.data import CharField, DatetimeField
from tortoise.fields.relational import ReverseRelation

from app import schemas
from app.models.base import AbstractResourceModel

from .mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models import Snapshot


class Whois(AbstractResourceModel, TimestampMixin):

    snapshots: ReverseRelation["Snapshot"]

    created = DatetimeField(null=True)
    updated = DatetimeField(null=True)
    expires = DatetimeField(null=True)

    registrar = CharField(max_length=255, null=True)
    registrant_name = CharField(max_length=255, null=True)
    registrant_organization = CharField(max_length=255, null=True)

    def to_model(self) -> schemas.Whois:
        return schemas.Whois.from_orm(self)

    class Meta:
        table = "whoises"
