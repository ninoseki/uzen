from typing import List, Optional

from fastapi import APIRouter, Depends

from app import schemas
from app.api.dependencies.snapshot import SearchFilters
from app.services.yara_scanner import YaraScanner

router = APIRouter()


@router.post(
    "/scan",
    response_model=List[schemas.YaraScanResult],
    response_description="Returns a list of matched snapshots",
    summary="Perform YARA scans against snapshots",
    description="Perform YARA scans against snapshots (which can be narrowed down by filters)",
)
async def scan(
    payload: schemas.YaraScanPayload,
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
) -> List[schemas.YaraScanResult]:
    yara_scanner = YaraScanner(payload.source)
    results = await yara_scanner.scan_snapshots(
        payload.target, vars(filters), size=size, offset=offset
    )
    return results
