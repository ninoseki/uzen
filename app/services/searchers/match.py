from typing import Any, Dict, List, Optional, cast

from tortoise.expressions import Q

from app import dataclasses, models, schemas
from app.services.searchers import AbstractSearcher
from app.services.searchers.utils import convert_to_datetime


def build_query(filters: Dict[str, Any]) -> Q:
    queries: List[Q] = []

    rule_id = filters.get("rule_id")
    if rule_id is not None:
        queries.append(Q(rule_id=rule_id))

    snapshot_id = filters.get("snapshot_id")
    if snapshot_id is not None:
        queries.append(Q(snapshot_id=snapshot_id))

    from_at = filters.get("from_at")
    if from_at is not None:
        from_at = convert_to_datetime(from_at)
        queries.append(Q(created_at__gt=from_at))

    to_at = filters.get("to_at")
    if to_at is not None:
        to_at = convert_to_datetime(to_at)
        queries.append(Q(created_at__lt=to_at))

    return Q(*queries)


class MatchSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls,
        filters: Dict[str, Any],
        size: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> schemas.MatchesSearchResults:
        query = build_query(filters)
        instance = cls(
            model=models.Match,
            query=query,
            prefetch_related=["snapshot", "rule", "script"],
        )
        results = await instance._search(size=size, offset=offset)
        matches: List[schemas.Match] = [
            match.to_model() for match in cast(List[models.Match], results.results)
        ]
        return schemas.MatchesSearchResults(results=matches, total=results.total)

    @classmethod
    async def search_for_ids(
        cls,
        filters: Dict[str, Any],
        size: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dataclasses.SearchResultsForIDs:
        query = build_query(filters)
        instance = cls(
            model=models.Match,
            query=query,
            prefetch_related=["snapshot", "rule", "script"],
        )
        return await instance._search_for_ids(size=size, offset=offset)
