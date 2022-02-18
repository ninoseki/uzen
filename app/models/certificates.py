from typing import TYPE_CHECKING

from tortoise.fields.relational import ReverseRelation

from app import schemas
from app.models.base import AbstractResourceModel

from .mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models import Snapshot


class Certificate(AbstractResourceModel, TimestampMixin):
    snapshots: ReverseRelation["Snapshot"]

    def to_model(self) -> schemas.Certificate:
        return schemas.Certificate.from_orm(self)

    class Meta:
        table = "certificates"
