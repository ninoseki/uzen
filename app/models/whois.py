from tortoise import fields

from app import schemas
from app.models.base import AbstractResourceModel
from app.models.mixins import TimestampMixin


class Whois(AbstractResourceModel, TimestampMixin):

    snapshots: fields.ReverseRelation["Snapshot"]

    def to_model(self) -> schemas.Whois:
        return schemas.Whois.from_orm(self)

    class Meta:
        table = "whoises"
