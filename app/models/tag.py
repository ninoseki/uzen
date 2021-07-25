from typing import TYPE_CHECKING

from tortoise.fields.data import CharField
from tortoise.fields.relational import ManyToManyRelation

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin

if TYPE_CHECKING:
    from app.models import Snapshot


class Tag(AbstractBaseModel, TimestampMixin):
    name = CharField(max_length=64, unique=True)

    _snapshots: ManyToManyRelation["Snapshot"]

    def to_model(self) -> schemas.Tag:
        return schemas.Tag.from_orm(self)

    class Meta:
        table = "tags"