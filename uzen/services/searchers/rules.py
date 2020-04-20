from typing import List, cast
from uuid import UUID

from tortoise.query_utils import Q

from uzen.models.rules import Rule
from uzen.schemas.rules import Rule as RuleModel
from uzen.schemas.rules import SearchResults
from uzen.services.searchers import AbstractSearcher


class RuleSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls, filters: dict, size=None, offset=None, id_only=False,
    ) -> SearchResults:
        """Search rules.

        Arguments:
            filters {dict} -- Filters for rule search

        Keyword Arguments:
            size {[int]} -- Nmber of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})

        Returns:
            SearchResults -- A list of rules and total count
        """
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

        query = Q(*queries)

        # Run search
        instance = cls(model=Rule, query=query)
        results = await instance._search(size=size, offset=offset, id_only=id_only)

        if id_only:
            return SearchResults(
                results=cast(List[UUID], results.results), total=results.total
            )

        rules: List[RuleModel] = [
            rule.to_model() for rule in cast(List[Rule], results.results)
        ]
        return SearchResults(results=rules, total=results.total)
