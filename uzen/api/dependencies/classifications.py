from typing import Optional


async def classification_filters(snapshot_id: Optional[int] = None) -> dict:
    """Filters for classification search

    Keyword Arguments:
        snapshot_id {Optional[int]} -- Snapshot ID (default: {None})

    Returns:
        dict -- filters as a dict
    """
    return {
        "snapshot_id": snapshot_id,
    }
