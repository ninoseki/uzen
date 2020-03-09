from typing import Optional


async def script_filters(
    snapshot_id: Optional[int] = None, sha256: Optional[str] = None,
) -> dict:
    """Filters for script search

    Keyword Arguments:
        snapshot_id {Optional[int]} -- Snapshot ID (default: {None})
        sha256 {Optional[str]} -- SHA256 (default: {None})

    Returns:
        dict -- filters as a dict
    """
    return {
        "snapshot_id": snapshot_id,
        "sha256": sha256,
    }
