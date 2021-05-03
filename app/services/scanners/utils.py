from typing import Any, Dict, List, Optional

from tortoise.query_utils import Q

from app import schemas
from app.services.searchers.snapshot import SnapshotSearcher


async def search_snapshots(
    html_id: Optional[str] = None,
    id_only: bool = False,
    exclude_hostname: Optional[str] = None,
    exclude_ip_address: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None,
    size: Optional[int] = None,
    offset: Optional[int] = None,
) -> schemas.SnapshotsSearchResults:
    if filters is None:
        filters = {}

    additional_queries: List[Q] = [~Q(html__id=html_id)]

    if html_id is not None:
        additional_queries.append(~Q(html__id=html_id))

    if exclude_hostname is not None:
        additional_queries.append(~Q(hostname=exclude_hostname))

    if exclude_ip_address is not None:
        additional_queries.append(~Q(ip_address=exclude_ip_address))

    return await SnapshotSearcher.search(
        filters,
        size=size,
        offset=offset,
        id_only=id_only,
        additional_queries=additional_queries,
    )
