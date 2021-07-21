from datetime import datetime
from typing import Union
from uuid import UUID

from tortoise.fields.data import BooleanField, DatetimeField, IntField
from tortoise.transactions import in_transaction

from app.models.base import AbstractBaseModel
from app.models.mixin import TimestampMixin


class APIKey(AbstractBaseModel, TimestampMixin):
    is_active = BooleanField(default=True)
    last_queried_at = DatetimeField(null=True)
    total_queries = IntField(default=0)

    class Meta:
        table = "api_keys"

    async def revoke(self):
        async with in_transaction():
            self.is_active = False
            await self.save()

    async def activate(self):
        async with in_transaction():
            self.is_active = True
            await self.save()

    async def update_usage(self):
        async with in_transaction():
            self.total_queries += 1
            self.last_queried_at = datetime.now()
            await self.save()

    @classmethod
    async def is_active_key(cls, key: Union[str, UUID]) -> bool:
        first = await cls.filter(id=str(key)).first()
        if first is None:
            return False

        return first.is_active

    @classmethod
    async def get_by_id(cls, id_: Union[str, UUID]) -> "APIKey":
        return await cls.get(id=str(id_))
