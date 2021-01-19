from tortoise import fields

from app import schemas
from app.models.base import AbstractResourceModel
from app.models.mixins import TimestampMixin


class File(AbstractResourceModel, TimestampMixin):

    scripts: fields.ReverseRelation["Script"]

    def to_model(self) -> schemas.File:
        return schemas.File.from_orm(self)

    class Meta:
        table = "files"
