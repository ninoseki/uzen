from tortoise import fields
from tortoise.models import Model

from app.models.mixin import CountMixin, DeleteMixin


class AbstractBaseModel(Model, DeleteMixin, CountMixin):
    id = fields.UUIDField(pk=True)

    class Meta:
        abstract = True


class AbstractResourceModel(Model, DeleteMixin, CountMixin):
    id = fields.CharField(max_length=64, pk=True)
    content = fields.TextField()

    class Meta:
        abstract = True
