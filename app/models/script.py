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
    from app.dataclasses import ScriptFile
    from app.models import File, Snapshot


class Script(TimestampMixin, AbstractBaseModel):
    url = TextField()
    snapshot: ForeignKeyRelation["Snapshot"] = ForeignKeyField(
        "models.Snapshot",
        related_name="_scripts",
        to_field="id",
        on_delete=CASCADE,
    )

    file: ForeignKeyRelation["File"] = ForeignKeyField(
        "models.File", related_name="scripts", on_delete=RESTRICT
    )

    def to_model(self) -> schemas.Script:
        self.url = normalize_url(str(self.url))
        return schemas.Script.from_orm(self)

    @classmethod
    async def save_script_files(
        cls, script_files: List["ScriptFile"], snapshot_id: UUID
    ) -> None:
        files = [script_file.file for script_file in script_files]
        for file in files:
            try:
                await file.save()
            except IntegrityError:
                # ignore the integrity error
                # e.g. tortoise.exceptions.IntegrityError: UNIQUE constraint failed: files.id
                pass

        scripts = [script_file.script for script_file in script_files]
        for script in scripts:
            script.snapshot_id = snapshot_id
        await cls.bulk_create(scripts)

    class Meta:
        table = "scripts"
