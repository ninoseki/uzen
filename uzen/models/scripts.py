from tortoise import fields
from tortoise.models import Model

from uzen.models.schemas.scripts import Script as ScriptModel


class Script(Model):
    id = fields.IntField(pk=True)
    url = fields.TextField()
    content = fields.TextField()
    sha256 = fields.CharField(max_length=64)
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshot: fields.ForeignKeyRelation["Snapshot"] = fields.ForeignKeyField(
        "models.Snapshot", related_name="_scripts", to_field="id"
    )

    def to_model(self) -> ScriptModel:
        return ScriptModel.from_orm(self)

    class Meta:
        table = "scripts"
