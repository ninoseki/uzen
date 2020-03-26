from typing import Optional


async def dns_record_filters(
    snapshot_id: Optional[int] = None, value: Optional[str] = None,
) -> dict:
    """Filters for DNS recrods search

    Keyword Arguments:
        snapshot_id {Optional[int]} -- Snapshot ID (default: {None})
        value {Optional[str]} -- a value of a DNS record (default: {None})

    Returns:
        dict -- filters as a dict
    """
    return {
        "snapshot_id": snapshot_id,
        "value": value,
    }
