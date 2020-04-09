import datetime
from typing import List, Union

from tortoise.query_utils import Q

from uzen.models.matches import Match


def convert_to_datetime(s: str) -> datetime.datetime:
    return datetime.datetime.strptime(s, "%Y-%m-%d")


class MatchSearcher:
    @staticmethod
    async def search_all(query: Q, id_only=False) -> Union[List[Match], int]:
        if id_only:
            return await Match.filter(query).values_list("id", flat=True)

        return await Match.filter(query).prefetch_related("snapshot", "rule")

    @staticmethod
    async def search_with_size(
        query: Q, size=100, id_only=False
    ) -> Union[List[Match], int]:
        if id_only:
            return await Match.filter(query).limit(size).values_list("id", flat=True)

        return (
            await Match.filter(query).limit(size).prefetch_related("snapshot", "rule")
        )

    @staticmethod
    async def search_with_size_and_offset(
        query: Q, offset=0, size=100, id_only=False
    ) -> Union[List[Match], int]:
        if id_only:
            return (
                await Match.filter(query)
                .offset(offset)
                .limit(size)
                .values_list("id", flat=True)
            )

        return (
            await Match.filter(query)
            .offset(offset)
            .limit(size)
            .prefetch_related("snapshot", "rule")
        )

    @staticmethod
    async def search(
        filters: dict, size=None, offset=None, id_only=False, count_only=False
    ) -> Union[List[Match], int]:
        """Search matches

        Arguments:
            filters {dict} -- Filters for match search

        Keyword Arguments:
            size {[int]} -- Nmber of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})
            count_only {bool} -- Whether to return only a count of results (default: {False})

        Returns:
            Union[List[Match], int] -- A list of matches or count of the list
        """
        queries: List[Q] = []
        query = Q(*queries)

        if count_only:
            return await Match.filter(query).count()

        if size is not None and offset is None:
            return await MatchSearcher.search_with_size(
                query, size=size, id_only=id_only
            )

        size = 100 if size is None else size
        if offset is not None:
            return await MatchSearcher.search_with_size_and_offset(
                query, size=size, offset=offset, id_only=id_only
            )

        return await MatchSearcher.search_all(query, id_only=id_only)
