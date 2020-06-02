from typing import List, cast
from uuid import UUID

from tortoise.query_utils import Q

from uzen.models.snapshots import Snapshot
from uzen.schemas.snapshots import SearchResults, SimplifiedSnapshot
from uzen.services.searchers import AbstractSearcher
from uzen.services.searchers.utils import convert_to_datetime


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

        url = filters.get("url")
        if url is not None:
            queries.append(Q(url=url))

        status = filters.get("status")
        if status is not None:
            queries.append(Q(status=status))

        hostname = filters.get("hostname")
        if hostname is not None:
            queries.append(Q(hostname=hostname))

        ip_address = filters.get("ip_address")
        if ip_address is not None:
            queries.append(Q(ip_address=ip_address))

        asn = filters.get("asn")
        if asn is not None:
            queries.append(Q(asn=asn))

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
            queries.append(Q(created_at__gt=convert_to_datetime(from_at)))

        to_at = filters.get("to_at")
        if to_at is not None:
            queries.append(Q(created_at__lt=convert_to_datetime(to_at)))

        query = Q(*queries)

        # Run search
        instance = cls(
            model=Snapshot, query=query, values=SimplifiedSnapshot.field_keys()
        )

        results = await instance._search(size=size, offset=offset, id_only=id_only)

        if id_only:
            return SearchResults(
                results=cast(List[UUID], results.results), total=results.total
            )

        results_ = cast(List[dict], results.results)
        return SearchResults(
            results=[SimplifiedSnapshot(**result) for result in results_],
            total=results.total,
        )
