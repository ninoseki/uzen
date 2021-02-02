from typing import List, cast
from uuid import UUID

from tortoise.query_utils import Q

from app import models, schemas
from app.services.searchers import AbstractSearcher
from app.services.searchers.utils import convert_to_datetime


class MatchSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls, filters: dict, size=None, offset=None, id_only=False
    ) -> schemas.MatchesSearchResults:
        """Search matches

        Arguments:
            filters {dict} -- Filters for match search

        Keyword Arguments:
            size {[int]} -- Nmber of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})

        Returns:
            SearchResults -- A list of matches and total count
        """
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

        query = Q(*queries)

        # Run search
        instance = cls(
            model=models.Match,
            query=query,
            prefetch_related=["snapshot", "rule", "script"],
        )
        results = await instance._search(size=size, offset=offset, id_only=id_only)

        if id_only:
            return schemas.MatchesSearchResults(
                results=cast(List[UUID], results.results), total=results.total
            )

        matches: List[schemas.Match] = [
            match.to_model() for match in cast(List[models.Match], results.results)
        ]
        return schemas.MatchesSearchResults(results=matches, total=results.total)