from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, AnyHttpUrl
from typing import List, Optional
import yara

from uzen.browser import Browser
from uzen.models import SnapshotModel, SnapshotBaseModel
from uzen.services.yara_scanner import YaraScanner


router = APIRouter()


class ScanPayload(BaseModel):
    source: str
    target: Optional[str]


@router.post("/scan", response_model=List[SnapshotModel])
async def scan(payload: ScanPayload, hostname: str = None, ip_address: str = None, asn: str = None, server: str = None, content_type: str = None, sha256: str = None, from_at: str = None, to_at: str = None):
    """
    Make a YARA scan against snapshots
    """
    source = payload.source
    target = payload.target or "body"

    try:
        yara_scanner = YaraScanner(source)
    except yara.Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    filters = {
        "hostname": hostname,
        "ip_address": ip_address,
        "asn": asn,
        "server": server,
        "content_type": content_type,
        "sha256": sha256,
        "from_at": from_at,
        "to_at": to_at,
    }
    snapshots = await yara_scanner.scan_snapshots(target, filters)
    return [snapshot.to_pandantic_model() for snapshot in snapshots]


class OneshotPayload(BaseModel):
    url: AnyHttpUrl
    source: str
    target: Optional[str]


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
    target = payload.target or "body"

    try:
        yara_scanner = YaraScanner(source)
    except yara.Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    snapshot = await Browser.take_snapshot(url)

    data = snapshot.to_dict().get(target, "")
    matches = yara_scanner.match(data)
    matched = True if len(matches) > 0 else False

    return OneshotResponse(snapshot=snapshot.to_base_model(), matched=matched)
