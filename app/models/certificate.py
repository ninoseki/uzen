from tortoise import fields

from app import schemas
from app.models.base import AbstractResourceModel
from app.models.mixin import TimestampMixin


class Certificate(AbstractResourceModel, TimestampMixin):
    snapshots: fields.ReverseRelation["Snapshot"]  # noqa F821

    not_after = fields.DatetimeField(null=True)
    not_before = fields.DatetimeField(null=True)

    subject = fields.CharField(max_length=255, null=True)
    issuer = fields.CharField(max_length=255, null=True)

    def to_model(self) -> schemas.Certificate:
        return schemas.Certificate.from_orm(self)

    class Meta:
        table = "certificates"
