from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, AnyHttpUrl
from typing import List, Optional
import yara

from uzen.browser import Browser
from uzen.models import SnapshotModel, SnapshotBaseModel
from uzen.services.yara_scanner import YaraScanner
from uzen.dependencies import search_filters

router = APIRouter()


class ScanPayload(BaseModel):
    source: str = Field(
        None,
        title="YARA rule",
        description="String containing the rules code"
    )
    target: Optional[str] = Field(
        "body",
        title="Target to scan",
        description="Target field to scan (body, whois or certificate)"
    )


@router.post(
    "/scan",
    response_model=List[SnapshotModel],
    response_description="Returns a list of matched snapshots",
    summary="Perform YARA scans against snapshtos",
    description="Perform YARA scans against snapshtos (which can be narrowed down by filters)",
)
async def scan(payload: ScanPayload, filters: dict = Depends(search_filters)) -> List[SnapshotModel]:
    source = payload.source
    target = payload.target

    try:
        yara_scanner = YaraScanner(source)
    except yara.Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    snapshots = await yara_scanner.scan_snapshots(target, filters)
    return [snapshot.to_full_model() for snapshot in snapshots]


class OneshotPayload(ScanPayload):
    url: AnyHttpUrl


class OneshotResponse(BaseModel):
    snapshot: SnapshotBaseModel = Field(
        None,
        title="Snapshot model",
        description="Snapshot model without id & created_at fields"
    )
    matched: bool = Field(
        None,
        title="whether matched or not",
        description="whether matched or not"
    )


@router.post(
    "/oneshot",
    response_model=OneshotResponse,
    response_description="Returns a snapshot and a matching result",
    summary="Perform a YARA scan against a website",
    description="Perform oneshot YARA scan against a website",
)
async def oneshot(payload: OneshotPayload) -> OneshotResponse:
    source = payload.source
    url = payload.url
    target = payload.target

    try:
        yara_scanner = YaraScanner(source)
    except yara.Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    snapshot = await Browser.take_snapshot(url)

    data = snapshot.to_dict().get(target, "")
    matches = yara_scanner.match(data)
    matched = True if len(matches) > 0 else False

    return OneshotResponse(snapshot=snapshot.to_base_model(), matched=matched)
