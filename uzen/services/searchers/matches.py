from typing import List, Union, cast

from tortoise.query_utils import Q

from uzen.models.matches import Match
from uzen.services.searchers import AbstractSearcher


class MatchSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls, filters: dict, size=None, offset=None, id_only=False, count_only=False
    ) -> Union[List[Match], List[int], int]:
        """Search matches

        Arguments:
            filters {dict} -- Filters for match search

        Keyword Arguments:
            size {[int]} -- Nmber of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})
            count_only {bool} -- Whether to return only a count of results (default: {False})

        Returns:
            Union[List[Match], List[int], int] -- A list of matches or count of the list
        """
        queries: List[Q] = []
        query = Q(*queries)

        # Run search
        instance = cls(model=Match, query=query, prefetch_related=["snapshot", "rule"])
        results = await instance._search(
            size=size, offset=offset, id_only=id_only, count_only=count_only
        )

        return cast(Union[List[Match], int], results)
