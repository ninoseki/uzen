from __future__ import annotations

from abc import ABC, abstractmethod

from tortoise.models import Model, QuerySet
from tortoise.query_utils import Q

from app import dataclasses


class AbstractSearcher(ABC):
    def __init__(
        self,
        model: type[Model],
        query: Q,
        values: list[str] | None = None,
        prefetch_related: list[str] | None = None,
    ):
        if prefetch_related is None:
            prefetch_related = []

        self.model = model
        self.query = query
        self.values = values
        self.prefetch_related = prefetch_related

    async def _total(self) -> int:
        return await self.model.filter(self.query).count()

    def build_queryset(
        self, size: int | None = None, offset: int | None = None, id_only=False
    ) -> QuerySet[type[Model]]:
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
        self,
        size: int | None = None,
        offset: int | None = None,
        id_only=False,
    ) -> dataclasses.SearchResults:
        total = await self._total()
        queryset = self.build_queryset(size=size, offset=offset, id_only=id_only)
        results = await queryset
        return dataclasses.SearchResults(results=results, total=total)

    @classmethod
    @abstractmethod
    async def search(
        cls,
        filters: dict,
        size: int | None = None,
        offset: int | None = None,
        id_only=False,
    ):
        """Search a table.

        Override this method in child classes.
        """
        raise NotImplementedError()
