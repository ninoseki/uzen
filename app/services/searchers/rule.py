from typing import Any, Dict, List, Optional, cast

from tortoise.expressions import Q

from app import dataclasses, models, schemas
from app.services.searchers import AbstractSearcher


def build_query(filters: Dict[str, Any]) -> Q:
    # build queirs from filters
    queries = []

    name = filters.get("name")
    if name is not None:
        queries.append(Q(name__contains=name))

    target = filters.get("target")
    if target is not None:
        queries.append(Q(target=target))

    source = filters.get("source")
    if source is not None:
        queries.append(Q(source__contains=source))

    return Q(*queries)


class RuleSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls,
        filters: Optional[Dict[str, Any]] = None,
        size: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> schemas.RulesSearchResults:
        if filters is None:
            filters = {}

        query = build_query(filters)
        # Run search
        instance = cls(model=models.Rule, query=query)
        results = await instance._search(size=size, offset=offset)

        rules = [rule.to_model() for rule in cast(List[models.Rule], results.results)]
        return schemas.RulesSearchResults(results=rules, total=results.total)

    @classmethod
    async def search_for_ids(
        cls,
        filters: Dict[str, Any] = None,
        size: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dataclasses.SearchResultsForIDs:
        if filters is None:
            filters = {}

        query = build_query(filters)
        # Run search
        instance = cls(model=models.Rule, query=query)
        return await instance._search_for_ids(size=size, offset=offset)
