from typing import List, Optional

from app import schemas
from app.services.yara_scanner import YaraScanner


async def yara_scan_task(
    ctx: dict, payload: schemas.YaraScanPayloadWithSearchOptions
) -> schemas.JobResultWrapper:
    scan_results: Optional[List[schemas.YaraScanResult]] = None
    try:
        yara_scanner = YaraScanner(payload.source)
        scan_results = await yara_scanner.scan_snapshots(
            payload.target, payload.filters, size=payload.size, offset=payload.offset
        )
    except Exception as e:
        return schemas.JobResultWrapper(result=scan_results, error=str(e))

    return schemas.JobResultWrapper(result=scan_results, error=None)
