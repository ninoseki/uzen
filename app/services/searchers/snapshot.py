from typing import List, Optional, cast

from tortoise.expressions import Q

from app import dataclasses, models, schemas
from app.services.searchers import AbstractSearcher
from app.services.searchers.utils import convert_to_datetime


def build_query(
    filters: schemas.SnapshotSearchFilters,
    additional_queries: Optional[List[Q]] = None,
) -> Q:
    queries = []

    if filters.url is not None:
        queries.append(Q(url=filters.url))

    if filters.status is not None:
        queries.append(Q(status=filters.status))

    if filters.hostname is not None:
        queries.append(Q(hostname=filters.hostname))

    if filters.ip_address is not None:
        queries.append(Q(ip_address=filters.ip_address))

    if filters.asn is not None:
        queries.append(Q(asn=filters.asn))

    if filters.hash is not None:
        queries.append(
            Q(html__id=filters.hash)
            | Q(scripts__file_id=filters.hash)
            | Q(stylesheets__file_id=filters.hash)
        )

    if filters.certificate_fingerprint is not None:
        queries.append(Q(certificate__id=filters.certificate_fingerprint))

    if filters.tag is not None:
        queries.append(Q(tags__name=filters.tag))

    if filters.from_at is not None:
        queries.append(Q(created_at__gt=convert_to_datetime(filters.from_at)))

    if filters.to_at is not None:
        queries.append(Q(created_at__lt=convert_to_datetime(filters.to_at)))

    if filters.search_after is not None:
        queries.append(Q(id__gt=filters.search_after))

    if filters.search_before is not None:
        queries.append(Q(id__lt=filters.search_before))

    if additional_queries is not None:
        queries.extend(additional_queries)

    return Q(*queries)


class SnapshotSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls,
        filters: schemas.SnapshotSearchFilters,
        size: Optional[int] = None,
        offset: Optional[int] = None,
        additional_queries: Optional[List[Q]] = None,
    ) -> schemas.SnapshotsSearchResults:
        query = build_query(filters, additional_queries)

        # Run search
        instance = cls(
            model=models.Snapshot,
            query=query,
            prefetch_related=["tags"],
            values=schemas.PlainSnapshot.field_keys(),
            group_by=["id"],
        )
        results = await instance._search(size=size, offset=offset)
        snapshots = cast(List[dict], results.results)
        return schemas.SnapshotsSearchResults(
            results=[
                schemas.PlainSnapshot.parse_obj(snapshot) for snapshot in snapshots
            ],
            total=results.total,
        )

    @classmethod
    async def search_for_ids(
        cls,
        filters: schemas.SnapshotSearchFilters,
        size: Optional[int] = None,
        offset: Optional[int] = None,
        additional_queries: Optional[List[Q]] = None,
    ) -> dataclasses.SearchResultsForIDs:
        query = build_query(filters, additional_queries)
        # Run search
        instance = cls(model=models.Snapshot, query=query, prefetch_related=["tags"])
        return await instance._search_for_ids(size=size, offset=offset)
