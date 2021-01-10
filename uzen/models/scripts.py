from tortoise import fields
from tortoise.models import Model

from uzen.models.base import AbstractBaseModel
from uzen.models.mixins import TimestampMixin
from uzen.schemas.scripts import File as FileModel
from uzen.schemas.scripts import Script as ScriptModel


def normalize_url(url: str) -> str:
    """Normalize URL

    Arguments:
        url {str} -- A URL

    Returns:
        str -- A normalized URL
    """
    # remove string after "?" to comply with Pydantic AnyHttpUrl validation
    # e.g. http:/example.com/test.js?foo=bar to http://example.com/test.js
    splitted = url.split("?")
    return splitted[0]


class Script(TimestampMixin, AbstractBaseModel):
    url = fields.TextField()
    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot",
        related_name="_scripts",
        to_field="id",
        on_delete=fields.CASCADE,
    )

    file: fields.ForeignKeyRelation["File"] = fields.ForeignKeyField(
        "models.File", related_name="scripts", on_delete=fields.RESTRICT
    )

    def to_model(self) -> ScriptModel:
        self.url = normalize_url(self.url)
        return ScriptModel.from_orm(self)

    class Meta:
        table = "scripts"


class File(Model):
    id = fields.CharField(max_length=64, pk=True)
    content = fields.TextField()

    scripts: fields.ReverseRelation["Script"]

    def to_model(self) -> FileModel:
        return FileModel.from_orm(self)

    class Meta:
        table = "files"
