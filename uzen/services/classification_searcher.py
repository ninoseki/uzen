from typing import List
from tortoise.query_utils import Q

from uzen.models.classifications import Classification


class ClassificationSearcher:
    @staticmethod
    async def search(filters: dict) -> List[Classification]:
        """Search classifications

        Arguments:
            filters {dict} -- Filters for classification search

        Returns:
            List[Classification] -- a list of matched classifications
        """
        queries = []

        snapshot_id = filters.get("snapshot_id")
        if snapshot_id is not None:
            queries.append(Q(snapshot_id=snapshot_id))

        query = Q(*queries)

        return await Classification.filter(query).order_by("-id")
