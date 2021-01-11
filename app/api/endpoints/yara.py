from typing import List, Optional

from fastapi import APIRouter, Depends

from app.api.dependencies.snapshots import SearchFilters
from app.schemas.yara import ScanPayload, ScanResult
from app.services.yara_scanner import YaraScanner

router = APIRouter()


@router.post(
    "/scan",
    response_model=List[ScanResult],
    response_description="Returns a list of matched snapshots",
    summary="Perform YARA scans against snapshtos",
    description="Perform YARA scans against snapshtos (which can be narrowed down by filters)",
)
async def scan(
    payload: ScanPayload,
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
) -> List[ScanResult]:
    yara_scanner = YaraScanner(payload.source)
    results = await yara_scanner.scan_snapshots(
        payload.target, vars(filters), size=size, offset=offset
    )
    return results
