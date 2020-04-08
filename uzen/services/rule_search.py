from typing import List, Union

from tortoise.query_utils import Q

from uzen.models.rules import Rule


class RuleSearcher:
    @staticmethod
    async def search_all(query: Q, id_only=False) -> Union[List[Rule], int]:
        if id_only:
            return await Rule.filter(query).order_by("-id").values_list("id", flat=True)

        return await Rule.filter(query).order_by("-id")

    @staticmethod
    async def search_with_size(
        query: Q, size=100, id_only=False
    ) -> Union[List[Rule], int]:
        if id_only:
            return (
                await Rule.filter(query)
                .order_by("-id")
                .limit(size)
                .values_list("id", flat=True)
            )

        return await Rule.filter(query).order_by("-id").limit(size)

    @staticmethod
    async def search_with_size_and_offset(
        query: Q, offset=0, size=100, id_only=False
    ) -> Union[List[Rule], int]:
        if id_only:
            return (
                await Rule.filter(query)
                .order_by("-id")
                .offset(offset)
                .limit(size)
                .values_list("id", flat=True)
            )

        return await Rule.filter(query).order_by("-id").offset(offset).limit(size)

    @staticmethod
    async def search(
        filters: dict, size=None, offset=None, id_only=False, count_only=False
    ) -> Union[List[Rule], int]:
        """Search rule

        Arguments:
            filters {dict} -- Filters for rule search

        Keyword Arguments:
            size {[int]} -- Nmber of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})
            count_only {bool} -- Whether to return only a count of results (default: {False})

        Returns:
            Union[List[Rule], int] -- A list of rules or count of the list
        """
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

        if count_only:
            return await Rule.filter(query).count()

        if size is not None and offset is None:
            return await RuleSearcher.search_with_size(
                query, size=size, id_only=id_only
            )

        size = 100 if size is None else size
        if offset is not None:
            return await RuleSearcher.search_with_size_and_offset(
                query, size=size, offset=offset, id_only=id_only
            )

        return await RuleSearcher.search_all(query, id_only=id_only)
