from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Type

from tortoise.models import Model, QuerySet
from tortoise.query_utils import Q

from uzen.schemas.search import SearchResults


class AbstractSearcher(ABC):
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

    def build_queryset(
        self, size: Optional[int] = None, offset: Optional[int] = None, id_only=False
    ) -> QuerySet[Type[Model]]:
        size = 100 if size is None else size

        queryset = self.model.filter(self.query).limit(size)
        if offset is not None:
            queryset = queryset.offset(offset)

        if id_only:
            return queryset.values_list("id", flat=True)

        if self.values is not None:
            return queryset.values(*self.values)

        return queryset.prefetch_related(*self.prefetch_related)

    async def _search(
        self, size: Optional[int] = None, offset: Optional[int] = None, id_only=False,
    ) -> SearchResults:
        total = await self._total()
        queryset = self.build_queryset(size=size, offset=offset, id_only=id_only)
        results = await queryset
        return SearchResults(results=results, total=total)

    @classmethod
    @abstractmethod
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
