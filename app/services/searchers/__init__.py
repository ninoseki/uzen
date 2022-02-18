from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from tortoise.expressions import Q, Subquery
from tortoise.models import Model, QuerySet

from app import dataclasses, types


class AbstractSearcher(ABC):
    def __init__(
        self,
        model: type[Model],
        query: Q,
        values: list[str] | None = None,
        group_by: list[str] | None = None,
        prefetch_related: list[str] | None = None,
    ):
        if prefetch_related is None:
            prefetch_related = []

        self.model = model
        self.query = query
        self.values = values
        self.group_by = group_by
        self.prefetch_related = prefetch_related

    async def _total(self) -> int:
        return await self.model.filter(
            pk__in=Subquery(self.model.filter(self.query).group_by("id").values("id"))
        ).count()

    def _build_queryset(
        self, size: int | None = None, offset: int | None = None
    ) -> QuerySet[type[Model]]:
        size = 100 if size is None else size

        queryset = self.model.filter(self.query).limit(size)
        if offset is not None:
            queryset = queryset.offset(offset)

        return queryset.prefetch_related(*self.prefetch_related)

    async def _search(
        self,
        size: int | None = None,
        offset: int | None = None,
    ) -> dataclasses.SearchResults:
        total = await self._total()

        queryset = self._build_queryset(size=size, offset=offset)

        if self.values is not None:
            if self.group_by is not None:
                results = await queryset.group_by(*self.group_by).values(*self.values)
            else:
                results = await queryset.values(*self.values)
        else:
            results = await queryset

        return dataclasses.SearchResults(results=results, total=total)

    async def _search_for_ids(
        self,
        size: int | None = None,
        offset: int | None = None,
    ) -> dataclasses.SearchResultsForIDs:
        total = await self._total()

        queryset = self._build_queryset(size=size, offset=offset)

        if self.group_by is not None:
            ids = await queryset.group_by(*self.group_by).values_list("id", flat=True)
        else:
            ids = await queryset.group_by("id").values_list("id", flat=True)

        results = [types.ULID.from_str(id) for id in ids]

        return dataclasses.SearchResultsForIDs(results=results, total=total)

    @classmethod
    @abstractmethod
    async def search(
        cls,
        filters: dict[str, Any],
        size: int | None = None,
        offset: int | None = None,
    ) -> Any:
        """Search a table.

        Override this method in child classes.
        """
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def search_for_ids(
        cls,
        filters: dict[str, Any],
        size: int | None = None,
        offset: int | None = None,
    ) -> dataclasses.SearchResultsForIDs:
        """Search a table for IDs.

        Override this method in child classes.
        """
        raise NotImplementedError()
