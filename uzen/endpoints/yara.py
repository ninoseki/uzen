from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, AnyHttpUrl
from typing import List, Optional
import yara

from uzen.browser import Browser
from uzen.models import SnapshotModel, SnapshotBaseModel
from uzen.services.yara_scanner import YaraScanner
from uzen.dependencies import search_filters

router = APIRouter()


class ScanPayload(BaseModel):
    source: str
    target: Optional[str] = "body"


@router.post("/scan", response_model=List[SnapshotModel])
async def scan(payload: ScanPayload, filters: dict = Depends(search_filters)):
    """
    Make a YARA scan against snapshots
    """
    source = payload.source
    target = payload.target

    try:
        yara_scanner = YaraScanner(source)
    except yara.Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    snapshots = await yara_scanner.scan_snapshots(target, filters)
    return [snapshot.to_full_model() for snapshot in snapshots]


class OneshotPayload(BaseModel):
    url: AnyHttpUrl
    source: str
    target: Optional[str] = "body"


class OneshotResponse(BaseModel):
    snapshot: SnapshotBaseModel
    matched: bool


@router.post("/oneshot", response_model=OneshotResponse)
async def oneshot(payload: OneshotPayload):
    """
    Make oneshot YARA scan against a URL
    """
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
