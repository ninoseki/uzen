from __future__ import annotations

from typing import List, Union, Optional, Type

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
    ) -> Union[List[Type[Model]], List[dict], List[int]]:
        if id_only:
            return await self.model.filter(self.query).values_list("id", flat=True)

        if self.values is not None:
            return await self.model.filter(self.query).values(*self.values)

        return await self.model.filter(self.query).prefetch_related(
            *self.prefetch_related
        )

    async def search_with_size(
        self, size=100, id_only=False
    ) -> Union[List[Type[Model]], List[dict], List[int]]:
        if id_only:
            return (
                await self.model.filter(self.query)
                .limit(size)
                .values_list("id", flat=True)
            )

        if self.values is not None:
            return await self.model.filter(self.query).limit(size).values(*self.values)

        return (
            await self.model.filter(self.query)
            .limit(size)
            .prefetch_related(*self.prefetch_related)
        )

    async def search_with_size_and_offset(
        self, offset=0, size=100, id_only=False
    ) -> Union[List[Type[Model]], List[dict], List[int]]:
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
        self, size=None, offset=None, id_only=False, count_only=False,
    ) -> Union[List[Type[Model]], List[dict], List[int], int]:
        if count_only:
            return await self.count()

        if size is not None and offset is None:
            return await self.search_with_size(size=size, id_only=id_only)

        size = 100 if size is None else size
        if offset is not None:
            return await self.search_with_size_and_offset(
                size=size, offset=offset, id_only=id_only
            )

        return await self.search_all(id_only=id_only)

    @classmethod
    async def search(
        cls, filters: dict, size=None, offset=None, id_only=False, count_only=False
    ):
        """Search a table.

        Override this method in child classes.
        """
        raise NotImplementedError()
