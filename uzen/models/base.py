from tortoise import fields
from tortoise.models import Model


class AbstractBaseModel(Model):
    id = fields.IntField(pk=True)

    class Meta:
        abstract = True
