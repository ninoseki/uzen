from typing import List, Optional, cast

from tortoise.expressions import Q

from app import dataclasses, models, schemas
from app.services.searchers.base import AbstractSearcher
from app.services.searchers.utils import convert_to_datetime

PREFETCH_RELATED = ["snapshot", "rule", "script"]


def build_query(filters: schemas.MatchSearchFilters) -> Q:
    queries: List[Q] = []

    if filters.rule_id is not None:
        queries.append(Q(rule_id=filters.rule_id))

    if filters.snapshot_id is not None:
        queries.append(Q(snapshot_id=filters.snapshot_id))

    if filters.from_at is not None:
        queries.append(Q(created_at__gt=convert_to_datetime(filters.from_at)))

    if filters.to_at is not None:
        queries.append(Q(created_at__lt=convert_to_datetime(filters.to_at)))

    if filters.search_after is not None:
        queries.append(Q(id__gt=filters.search_after))

    if filters.search_before is not None:
        queries.append(Q(id__lt=filters.search_before))

    return Q(*queries)


class MatchSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls,
        filters: schemas.MatchSearchFilters,
        size: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> schemas.MatchesSearchResults:
        query = build_query(filters)
        instance = cls(
            model=models.Match, query=query, prefetch_related=PREFETCH_RELATED
        )
        results = await instance._search(size=size, offset=offset)
        matches: List[schemas.Match] = [
            match.to_model() for match in cast(List[models.Match], results.results)
        ]
        return schemas.MatchesSearchResults(results=matches, total=results.total)

    @classmethod
    async def search_for_ids(
        cls,
        filters: schemas.MatchSearchFilters,
        size: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dataclasses.SearchResultsForIDs:
        query = build_query(filters)
        instance = cls(
            model=models.Match, query=query, prefetch_related=PREFETCH_RELATED
        )
        return await instance._search_for_ids(size=size, offset=offset)
