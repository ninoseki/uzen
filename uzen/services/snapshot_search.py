import datetime
from typing import List, Union

from tortoise.query_utils import Q

from uzen.models.schemas.snapshots import SearchResult
from uzen.models.snapshots import Snapshot


def convert_to_datetime(s: str) -> datetime.datetime:
    return datetime.datetime.strptime(s, "%Y-%m-%d")


def convert_to_simple_snapshot_models(snapshots: List[dict]):
    return [SearchResult(**snapshot) for snapshot in snapshots]


class SnapshotSearcher:
    @staticmethod
    async def search_all(query: Q, id_only=False) -> Union[List[SearchResult], int]:
        if id_only:
            return (
                await Snapshot.filter(query)
                .order_by("-id")
                .values_list("id", flat=True)
            )

        snapshots = (
            await Snapshot.filter(query)
            .order_by("-id")
            .values(*SearchResult.field_keys())
        )
        return convert_to_simple_snapshot_models(snapshots)

    @staticmethod
    async def search_with_size(
        query: Q, size=100, id_only=False
    ) -> Union[List[SearchResult], int]:
        if id_only:
            return (
                await Snapshot.filter(query)
                .order_by("-id")
                .limit(size)
                .values_list("id", flat=True)
            )

        snapshots = (
            await Snapshot.filter(query)
            .order_by("-id")
            .limit(size)
            .values(*SearchResult.field_keys())
        )
        return convert_to_simple_snapshot_models(snapshots)

    @staticmethod
    async def search_with_size_and_offset(
        query: Q, offset=0, size=100, id_only=False
    ) -> Union[List[SearchResult], int]:
        if id_only:
            return (
                await Snapshot.filter(query)
                .order_by("-id")
                .offset(offset)
                .limit(size)
                .values_list("id", flat=True)
            )

        snapshots = (
            await Snapshot.filter(query)
            .order_by("-id")
            .offset(offset)
            .limit(size)
            .values(*SearchResult.field_keys())
        )
        return convert_to_simple_snapshot_models(snapshots)

    @staticmethod
    async def search(
        filters: dict, size=None, offset=None, id_only=False, count_only=False
    ) -> Union[List[SearchResult], int]:
        """Search snapshots

        Arguments:
            filters {dict} -- Filters for snapshot search

        Keyword Arguments:
            size {[int]} -- Nmber of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})
            count_only {bool} -- Whether to return only a count of results (default: {False})

        Returns:
            Union[List[SearchResult], int] -- A list of simlified snapshot models or count of the list
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

        if count_only:
            return await Snapshot.filter(query).count()

        if size is not None and offset is None:
            return await SnapshotSearcher.search_with_size(
                query, size=size, id_only=id_only
            )

        size = 100 if size is None else size
        if offset is not None:
            return await SnapshotSearcher.search_with_size_and_offset(
                query, size=size, offset=offset, id_only=id_only
            )

        return await SnapshotSearcher.search_all(query, id_only=id_only)
