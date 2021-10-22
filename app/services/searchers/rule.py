from typing import Any, Dict, List, Optional, cast

from tortoise.query_utils import Q

from app import models, schemas, types
from app.services.searchers import AbstractSearcher


class RuleSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls,
        filters: Dict[str, Any],
        size: Optional[int] = None,
        offset: Optional[int] = None,
        id_only: bool = False,
    ) -> schemas.RulesSearchResults:
        """Search rules.

        Arguments:
            filters {dict} -- Filters for rule search

        Keyword Arguments:
            size {[int]} -- Number of results returned (default: {None})
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
        instance = cls(model=models.Rule, query=query)
        results = await instance._search(size=size, offset=offset, id_only=id_only)

        if id_only:
            return schemas.RulesSearchResults(
                results=cast(List[types.ULID], results.results), total=results.total
            )

        rules = [rule.to_model() for rule in cast(List[models.Rule], results.results)]
        return schemas.RulesSearchResults(results=rules, total=results.total)
