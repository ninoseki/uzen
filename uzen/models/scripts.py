from tortoise import fields

from uzen.models.base import AbstractBaseModel
from uzen.models.mixins import TimestampMixin
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
    content = fields.TextField()
    sha256 = fields.CharField(max_length=64)

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot",
        related_name="_scripts",
        to_field="id",
        on_delete=fields.CASCADE,
    )

    def to_model(self) -> ScriptModel:
        self.url = normalize_url(self.url)
        return ScriptModel.from_orm(self)

    class Meta:
        table = "scripts"
