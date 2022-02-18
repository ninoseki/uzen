from typing import TYPE_CHECKING

from tortoise.fields.relational import ReverseRelation

from app import schemas
from app.models.base import AbstractResourceModel

from .mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models import Script, Stylesheet


class File(AbstractResourceModel, TimestampMixin):

    scripts: ReverseRelation["Script"]
    stylesheets: ReverseRelation["Stylesheet"]

    def to_model(self) -> schemas.File:
        return schemas.File.from_orm(self)

    class Meta:
        table = "files"
