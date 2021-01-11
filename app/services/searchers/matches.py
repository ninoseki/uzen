from typing import List, cast
from uuid import UUID

from tortoise.query_utils import Q

from app.models.matches import Match
from app.schemas.matches import Match as MatchModel
from app.schemas.matches import SearchResults
from app.services.searchers import AbstractSearcher
from app.services.searchers.utils import convert_to_datetime


class MatchSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls, filters: dict, size=None, offset=None, id_only=False
    ) -> SearchResults:
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
            model=Match, query=query, prefetch_related=["snapshot", "rule", "script"]
        )
        results = await instance._search(size=size, offset=offset, id_only=id_only)

        if id_only:
            return SearchResults(
                results=cast(List[UUID], results.results), total=results.total
            )

        matches: List[MatchModel] = [
            match.to_model() for match in cast(List[Match], results.results)
        ]
        return SearchResults(results=matches, total=results.total)
