from tortoise.models import Model
from tortoise import fields

from uzen.models.snapshots import Snapshot


class Script(Model):
    id = fields.IntField(pk=True)
    url = fields.TextField()
    content = fields.TextField()
    sha256 = fields.CharField(max_length=64)
    created_at = fields.DatetimeField(auto_now_add=True)

    snapshot: fields.ForeignKeyRelation[Snapshot] = fields.ForeignKeyField(
        "models.Snapshot", related_name="scripts", to_field="id")

    class Meta:
        table = "scripts"
