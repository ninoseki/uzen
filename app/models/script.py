from tortoise import fields

from app import schemas
from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin


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

    def to_model(self) -> schemas.Script:
        self.url = normalize_url(self.url)
        return schemas.Script.from_orm(self)

    class Meta:
        table = "scripts"
