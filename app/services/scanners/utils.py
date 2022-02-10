from typing import List, Optional

from tortoise.expressions import Q

from app import dataclasses, schemas
from app.services.searchers.snapshot import SnapshotSearcher


def build_additional_queries(
    html_id: Optional[str] = None,
    exclude_hostname: Optional[str] = None,
    exclude_ip_address: Optional[str] = None,
) -> List[Q]:
    additional_queries: List[Q] = []

    if html_id is not None:
        additional_queries.append(~Q(html_id=html_id))

    if exclude_hostname is not None:
        additional_queries.append(~Q(hostname=exclude_hostname))

    if exclude_ip_address is not None:
        additional_queries.append(~Q(ip_address=exclude_ip_address))

    return additional_queries


async def search_snapshots(
    html_id: Optional[str] = None,
    exclude_hostname: Optional[str] = None,
    exclude_ip_address: Optional[str] = None,
    filters: Optional[schemas.SnapshotSearchFilters] = None,
    size: Optional[int] = None,
    offset: Optional[int] = None,
) -> schemas.SnapshotsSearchResults:
    if filters is None:
        filters = schemas.SnapshotSearchFilters()

    additional_queries = build_additional_queries(
        html_id, exclude_hostname, exclude_ip_address
    )

    return await SnapshotSearcher.search(
        filters,
        size=size,
        offset=offset,
        additional_queries=additional_queries,
    )


async def search_snapshots_for_ids(
    html_id: Optional[str] = None,
    exclude_hostname: Optional[str] = None,
    exclude_ip_address: Optional[str] = None,
    filters: Optional[schemas.SnapshotSearchFilters] = None,
    size: Optional[int] = None,
    offset: Optional[int] = None,
) -> dataclasses.SearchResultsForIDs:
    if filters is None:
        filters = schemas.SnapshotSearchFilters()

    additional_queries = build_additional_queries(
        html_id, exclude_hostname, exclude_ip_address
    )

    return await SnapshotSearcher.search_for_ids(
        filters,
        size=size,
        offset=offset,
        additional_queries=additional_queries,
    )
