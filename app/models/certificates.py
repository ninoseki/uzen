from tortoise import fields

from app import schemas
from app.models.base import AbstractResourceModel
from app.models.mixin import TimestampMixin


class Certificate(AbstractResourceModel, TimestampMixin):
    snapshots: fields.ReverseRelation["Snapshot"]

    def to_model(self) -> schemas.Certificate:
        return schemas.Certificate.from_orm(self)

    class Meta:
        table = "certificates"
