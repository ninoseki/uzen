from __future__ import annotations

from typing import List, Optional, Type

from tortoise.models import Model
from tortoise.query_utils import Q

from uzen.schemas.search import SearchResults


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

    async def _total(self) -> int:
        return await self.model.filter(self.query).count()

    async def _search(
        self, size: Optional[int] = None, offset: Optional[int] = None, id_only=False,
    ) -> SearchResults:
        total = await self._total()

        offset = 0 if offset is None else offset
        size = 100 if size is None else size

        if id_only:
            results = (
                await self.model.filter(self.query)
                .offset(offset)
                .limit(size)
                .values_list("id", flat=True)
            )
            return SearchResults(results=results, total=total)

        if self.values is not None:
            results = (
                await self.model.filter(self.query)
                .offset(offset)
                .limit(size)
                .values(*self.values)
            )
            return SearchResults(results=results, total=total)

        results = (
            await self.model.filter(self.query)
            .offset(offset)
            .limit(size)
            .prefetch_related(*self.prefetch_related)
        )
        return SearchResults(results=results, total=total)

    @classmethod
    async def search(
        cls,
        filters: dict,
        size: Optional[int] = None,
        offset: Optional[int] = None,
        id_only=False,
    ):
        """Search a table.

        Override this method in child classes.
        """
        raise NotImplementedError()
