from typing import Optional


async def search_filters(
    name: Optional[str] = None,
    target: Optional[str] = None,
    source: Optional[str] = None,
) -> dict:
    """Filters for snapshot search

    Keyword Arguments:
        name {Optional[str]} -- Name (default: {None})
        target {Optional[str]} -- Target (default: {None})
        source {Optional[str]} -- Source (default: {None})

    Returns:
        dict -- filters as a dict
    """
    return {
        "name": name,
        "target": target,
        "source": source,
    }
