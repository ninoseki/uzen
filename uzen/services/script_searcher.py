from typing import List
from tortoise.query_utils import Q

from uzen.models.scripts import Script


class ScriptSearcher:
    @staticmethod
    async def search(filters: dict) -> List[Script]:
        """Search scripts

        Arguments:
            filters {dict} -- Filters for script search

        Returns:
            List[Script] -- a list of matched scripts
        """
        queries = []

        snapshot_id = filters.get("snapshot_id")
        if snapshot_id is not None:
            queries.append(Q(snapshot_id=snapshot_id))

        sha256 = filters.get("sha256")
        if sha256 is not None:
            queries.append(Q(sha256=sha256))

        query = Q(*queries)

        return await Script.filter(query).order_by("-id")
