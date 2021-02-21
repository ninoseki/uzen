from typing import TYPE_CHECKING, List
from uuid import UUID

from tortoise.exceptions import IntegrityError
from tortoise.fields.base import CASCADE, RESTRICT
from tortoise.fields.data import TextField
from tortoise.fields.relational import ForeignKeyField, ForeignKeyRelation

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin
from app.utils.url import normalize_url

if TYPE_CHECKING:
    from app.dataclasses import StylesheetFile
    from app.models import File, Snapshot


class Stylesheet(TimestampMixin, AbstractBaseModel):
    url = TextField()
    snapshot: ForeignKeyRelation["Snapshot"] = ForeignKeyField(
        "models.Snapshot",
        related_name="_stylesheets",
        to_field="id",
        on_delete=CASCADE,
    )

    file: ForeignKeyRelation["File"] = ForeignKeyField(
        "models.File", related_name="stylesheets", on_delete=RESTRICT
    )

    def to_model(self) -> schemas.Stylesheet:
        self.url = normalize_url(str(self.url))
        return schemas.Stylesheet.from_orm(self)

    @classmethod
    async def save_stylesheet_files(
        cls, stylesheet_files: List["StylesheetFile"], snapshot_id: UUID
    ) -> None:
        files = [stylesheet_file.file for stylesheet_file in stylesheet_files]
        for file in files:
            try:
                await file.save()
            except IntegrityError:
                # ignore the intergrity error
                # e.g. tortoise.exceptions.IntegrityError: UNIQUE constraint failed: files.id
                pass

        stylesheets = [
            stylesheet_file.stylesheet for stylesheet_file in stylesheet_files
        ]
        for stylesheet in stylesheets:
            stylesheet.snapshot_id = snapshot_id

        await cls.bulk_create(stylesheets)

    class Meta:
        table = "stylesheets"
