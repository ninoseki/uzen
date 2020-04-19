from __future__ import annotations

from typing import List, Optional, Type, Union
from uuid import UUID

from tortoise.models import Model
from tortoise.query_utils import Q


class AbstractSearcher:
    def __init__(
        self,
        model: Type[Model],
        query: Q,
        values: Optional[List[str]] = None,
        prefetch_related: List[str] = [],
    ):
        self.model = model
        self.query = query
        self.values = values
        self.prefetch_related = prefetch_related

    async def count(self) -> int:
        return await self.model.filter(self.query).count()

    async def search_all(
        self, id_only=False
    ) -> Union[List[Type[Model]], List[dict], List[UUID]]:
        if id_only:
            return await self.model.filter(self.query).values_list("id", flat=True)

        if self.values is not None:
            return await self.model.filter(self.query).values(*self.values)

        return await self.model.filter(self.query).prefetch_related(
            *self.prefetch_related
        )

    async def search_with_size_and_offset(
        self, offset=0, size=100, id_only=False
    ) -> Union[List[Type[Model]], List[dict], List[UUID]]:
        if id_only:
            return (
                await self.model.filter(self.query)
                .offset(offset)
                .limit(size)
                .values_list("id", flat=True)
            )

        if self.values is not None:
            return (
                await self.model.filter(self.query)
                .offset(offset)
                .limit(size)
                .values(*self.values)
            )

        return (
            await self.model.filter(self.query)
            .offset(offset)
            .limit(size)
            .prefetch_related(*self.prefetch_related)
        )

    async def _search(
        self,
        size: Optional[int] = None,
        offset: Optional[int] = None,
        id_only=False,
        count_only=False,
    ) -> Union[List[Type[Model]], List[dict], List[UUID], int]:
        if count_only:
            return await self.count()

        offset = 0 if offset is None else offset

        size = 100 if size is None else size
        if offset is not None:
            return await self.search_with_size_and_offset(
                size=size, offset=offset, id_only=id_only
            )

        return await self.search_all(id_only=id_only)

    @classmethod
    async def search(
        cls,
        filters: dict,
        size: Optional[int] = None,
        offset: Optional[int] = None,
        id_only=False,
        count_only=False,
    ):
        """Search a table.

        Override this method in child classes.
        """
        raise NotImplementedError()
