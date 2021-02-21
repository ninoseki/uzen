from typing import TYPE_CHECKING

from tortoise.fields.relational import ReverseRelation

from app import schemas
from app.models.base import AbstractResourceModel
from app.models.mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models import Snapshot


class HTML(AbstractResourceModel, TimestampMixin):
    snapshots: ReverseRelation["Snapshot"]

    def to_model(self) -> schemas.HTML:
        return schemas.HTML.from_orm(self)

    class Meta:
        table = "htmls"
