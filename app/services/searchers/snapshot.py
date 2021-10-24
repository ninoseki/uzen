from typing import Any, Dict, List, Optional, cast

from tortoise.query_utils import Q

from app import dataclasses, models, schemas
from app.services.searchers import AbstractSearcher
from app.services.searchers.utils import convert_to_datetime


def build_query(
    filters: Dict[str, Any],
    additional_queries: Optional[List[Q]] = None,
) -> Q:
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

    hash = filters.get("hash")
    if hash is not None:
        queries.append(
            Q(html__id=hash) | Q(_scripts__file_id=hash) | Q(_stylesheets__file_id=hash)
        )

    certificate_fingerprint = filters.get("certificate_fingerprint")
    if certificate_fingerprint is not None:
        queries.append(Q(certificate__id=certificate_fingerprint))

    tag = filters.get("tag")
    if tag is not None:
        queries.append(Q(_tags__name=tag))

    from_at = filters.get("from_at")
    if from_at is not None:
        queries.append(Q(created_at__gt=convert_to_datetime(from_at)))

    to_at = filters.get("to_at")
    if to_at is not None:
        queries.append(Q(created_at__lt=convert_to_datetime(to_at)))

    if additional_queries is not None:
        queries.extend(additional_queries)

    return Q(*queries)


class SnapshotSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls,
        filters: Dict[str, Any],
        size: Optional[int] = None,
        offset: Optional[int] = None,
        additional_queries: Optional[List[Q]] = None,
    ) -> schemas.SnapshotsSearchResults:
        query = build_query(filters, additional_queries)
        # Run search
        instance = cls(model=models.Snapshot, query=query, prefetch_related=["_tags"])
        results = await instance._search(size=size, offset=offset)
        snapshots = cast(List[models.Snapshot], results.results)
        return schemas.SnapshotsSearchResults(
            results=[
                schemas.PlainSnapshot.from_orm(snapshot) for snapshot in snapshots
            ],
            total=results.total,
        )

    @classmethod
    async def search_for_ids(
        cls,
        filters: Dict[str, Any],
        size: Optional[int] = None,
        offset: Optional[int] = None,
        additional_queries: Optional[List[Q]] = None,
    ) -> dataclasses.SearchResultsForIDs:
        query = build_query(filters, additional_queries)
        # Run search
        instance = cls(model=models.Snapshot, query=query, prefetch_related=["_tags"])
        return await instance._search_for_ids(size=size, offset=offset)
