from typing import List, Optional

from app import schemas
from app.services.yara_scanner import YaraScanner


async def yara_scan_task(
    ctx: dict, payload: schemas.YaraScanPayloadWithSearchOptions
) -> List[schemas.YaraScanResult]:
    results: Optional[List[schemas.YaraScanResult]] = None
    try:
        yara_scanner = YaraScanner(payload.source)
        results = await yara_scanner.scan_snapshots(
            payload.target, payload.filters, size=payload.size, offset=payload.offset
        )
    except Exception as e:
        return {"scan_results": results, "error": str(e)}

    return {"scan_results": results, "error": None}
