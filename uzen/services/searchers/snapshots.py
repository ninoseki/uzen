from typing import List, Union, cast
from uuid import UUID

from tortoise.query_utils import Q

from uzen.models.snapshots import Snapshot
from uzen.schemas.snapshots import SearchResult
from uzen.services.searchers import AbstractSearcher
from uzen.services.searchers.utils import convert_to_datetime


def convert_to_simple_snapshot_models(snapshots: List[dict]):
    return [SearchResult(**snapshot) for snapshot in snapshots]


class SnapshotSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls, filters: dict, size=None, offset=None, id_only=False, count_only=False
    ) -> Union[List[SearchResult], List[UUID], int]:
        """Search snapshots

        Arguments:
            filters {dict} -- Filters for snapshot search

        Keyword Arguments:
            size {[int]} -- Nmber of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})
            count_only {bool} -- Whether to return only a count of results (default: {False})

        Returns:
            Union[List[SearchResult], List[UUID], int] -- A list of simlified snapshot models or count of the list
        """
        queries = []

        hostname = filters.get("hostname")
        if hostname is not None:
            queries.append(Q(hostname__contains=hostname))

        ip_address = filters.get("ip_address")
        if ip_address is not None:
            queries.append(Q(ip_address__contains=ip_address))

        asn = filters.get("asn")
        if asn is not None:
            queries.append(Q(asn__contains=asn))

        server = filters.get("server")
        if server is not None:
            queries.append(Q(server__contains=server))

        content_type = filters.get("content_type")
        if content_type is not None:
            queries.append(Q(content_type__contains=content_type))

        sha256 = filters.get("sha256")
        if sha256 is not None:
            queries.append(Q(sha256=sha256))

        from_at = filters.get("from_at")
        if from_at is not None:
            from_at = convert_to_datetime(from_at)
            queries.append(Q(created_at__gte=from_at))

        to_at = filters.get("to_at")
        if to_at is not None:
            to_at = convert_to_datetime(to_at)
            queries.append(Q(created_at__lte=to_at))

        query = Q(*queries)

        # Run search
        instance = cls(model=Snapshot, query=query, values=SearchResult.field_keys())

        if count_only:
            return await instance.count()

        results = await instance._search(
            size=size, offset=offset, id_only=id_only, count_only=count_only
        )

        if id_only:
            return cast(List[UUID], results)

        results = cast(List[dict], results)
        return [SearchResult(**result) for result in results]
