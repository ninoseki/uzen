from typing import List, cast
from uuid import UUID

from tortoise.query_utils import Q

from uzen.models.snapshots import Snapshot
from uzen.schemas.snapshots import SearchResult, SearchResults
from uzen.services.searchers import AbstractSearcher
from uzen.services.searchers.utils import convert_to_datetime


def convert_to_simple_snapshot_models(snapshots: List[dict]):
    return [SearchResult(**snapshot) for snapshot in snapshots]


class SnapshotSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls, filters: dict, size=None, offset=None, id_only=False,
    ) -> SearchResults:
        """Search snapshots

        Arguments:
            filters {dict} -- Filters for snapshot search

        Keyword Arguments:
            size {[int]} -- Nmber of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})

        Returns:
           SearchResults -- A list of simlified snapshots and total count
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

        results = await instance._search(size=size, offset=offset, id_only=id_only)

        if id_only:
            return SearchResults(
                results=cast(List[UUID], results.results), total=results.total
            )

        results_ = cast(List[dict], results.results)
        return SearchResults(
            results=[SearchResult(**result) for result in results_],
            total=results.total,
        )
