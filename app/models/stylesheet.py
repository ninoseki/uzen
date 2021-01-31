from typing import TYPE_CHECKING, List
from uuid import UUID

from tortoise import fields
from tortoise.exceptions import IntegrityError

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin
from app.utils.url import normalize_url

if TYPE_CHECKING:
    from app.dataclasses import StylesheetFile


class Stylesheet(TimestampMixin, AbstractBaseModel):
    url = fields.TextField()
    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot",
        related_name="_stylesheets",
        to_field="id",
        on_delete=fields.CASCADE,
    )

    file: fields.ForeignKeyRelation["File"] = fields.ForeignKeyField(
        "models.File", related_name="stylesheets", on_delete=fields.RESTRICT
    )

    def to_model(self) -> schemas.Stylesheet:
        self.url = normalize_url(self.url)
        return schemas.Stylesheet.from_orm(self)

    @classmethod
    async def save_stylesheet_files(
        cls, stylesheet_files: List["StylesheetFile"], snapshot_id: UUID
    ):
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
