from tortoise import fields

from app import schemas
from app.models.base import AbstractResourceModel
from app.models.mixins import TimestampMixin


class HTML(AbstractResourceModel, TimestampMixin):
    snapshots: fields.ReverseRelation["Snapshot"]

    def to_model(self) -> schemas.HTML:
        return schemas.HTML.from_orm(self)

    class Meta:
        table = "htmls"
