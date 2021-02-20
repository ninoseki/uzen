from tortoise import fields

from app import schemas
from app.models.base import AbstractResourceModel
from app.models.mixin import TimestampMixin


class Whois(AbstractResourceModel, TimestampMixin):

    snapshots: fields.ReverseRelation["Snapshot"]  # noqa F821

    created = fields.DatetimeField(null=True)
    updated = fields.DatetimeField(null=True)
    expires = fields.DatetimeField(null=True)

    registrar = fields.CharField(max_length=255, null=True)
    registrant_name = fields.CharField(max_length=255, null=True)
    registrant_organization = fields.CharField(max_length=255, null=True)

    def to_model(self) -> schemas.Whois:
        return schemas.Whois.from_orm(self)

    class Meta:
        table = "whoises"
