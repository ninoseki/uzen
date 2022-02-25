from typing import TYPE_CHECKING

from tortoise.fields.data import CharField
from tortoise.fields.relational import ManyToManyRelation

from app import schemas

from .base import AbstractBaseModel
from .mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models import Snapshot


class Tag(AbstractBaseModel, TimestampMixin):
    name = CharField(max_length=64, unique=True)

    snapshots: ManyToManyRelation["Snapshot"]

    def to_model(self) -> schemas.Tag:
        return schemas.Tag.from_orm(self)

    class Meta:
        table = "tags"
