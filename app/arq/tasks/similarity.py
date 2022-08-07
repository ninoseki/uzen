from typing import List, Optional

from app import schemas
from app.services.scanners import SimilarityScanner


async def similarity_scan_task(
    ctx_: dict, payload: schemas.SimilarityScanWithSearchOptions
) -> schemas.JobResultWrapper:
    scan_results: Optional[List[schemas.SimilarityScanResult]] = None

    try:
        scanner = SimilarityScanner(html=payload.html, threshold=payload.threshold)
        scan_results = await scanner.scan_snapshots(
            filters=payload.filters,
            size=payload.size,
            offset=payload.offset,
            exclude_hostname=payload.exclude_hostname,
            exclude_ip_address=payload.exclude_ip_address,
        )
    except Exception as e:
        return schemas.JobResultWrapper(result=scan_results, error=str(e))

    return schemas.JobResultWrapper(result=scan_results, error=None)
