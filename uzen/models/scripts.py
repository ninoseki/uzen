from tortoise import fields
from tortoise.models import Model
from pydantic import AnyHttpUrl, BaseModel
import datetime


from uzen.models.snapshots import Snapshot


class ScriptBaseModel(BaseModel):
    """Base Pydantic model for Script

    Note that this model doesn't have "id" and "created_at" fields.
    """

    url: AnyHttpUrl
    content: str
    sha256: str

    class Config:
        orm_mode = True


class ScriptModel(ScriptBaseModel):
    """Full Pydantic model for Snapshot

    """

    id: int
    created_at: datetime.datetime


class Script(Model):
    id = fields.IntField(pk=True)
    url = fields.TextField()
    content = fields.TextField()
    sha256 = fields.CharField(max_length=64)
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshot: fields.ForeignKeyRelation[Snapshot] = fields.ForeignKeyField(
        "models.Snapshot", related_name="scripts", to_field="id"
    )

    def to_full_model(self) -> ScriptModel:
        return ScriptModel.from_orm(self)

    class Meta:
        table = "scripts"
