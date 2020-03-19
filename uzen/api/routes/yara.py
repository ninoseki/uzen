from typing import List, cast

import yara
from fastapi import APIRouter, Depends, HTTPException

from uzen.api.dependencies.snapshots import search_filters
from uzen.models.schemas.yara import OneshotPayload, OneshotResponse, ScanPayload
from uzen.models.snapshots import SearchResultModel
from uzen.services.browser import Browser
from uzen.services.dns_records import DnsRecordBuilder
from uzen.services.scripts import ScriptBuilder
from uzen.services.yara_scanner import YaraScanner

router = APIRouter()


@router.post(
    "/scan",
    response_model=List[SearchResultModel],
    response_description="Returns a list of matched snapshots",
    summary="Perform YARA scans against snapshtos",
    description="Perform YARA scans against snapshtos (which can be narrowed down by filters)",
)
async def scan(
    payload: ScanPayload, filters: dict = Depends(search_filters)
) -> List[SearchResultModel]:
    source = payload.source
    target = payload.target

    try:
        yara_scanner = YaraScanner(source)
    except yara.Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    snapshots = await yara_scanner.scan_snapshots(target, filters)
    return snapshots


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
    scripts = ScriptBuilder.build_from_snapshot(snapshot)
    records = DnsRecordBuilder.build_from_snapshot(snapshot)

    matched = False
    if target == "script":
        for script in scripts:
            matches = yara_scanner.match(script.content)
            if len(matches) > 0:
                matched = True
                break
    else:
        data = snapshot.to_dict().get(target, "")
        matches = yara_scanner.match(data)
        matched = True if len(matches) > 0 else False

    return OneshotResponse(
        snapshot=snapshot.to_base_model(),
        scripts=scripts,
        dnsRecords=records,
        matched=matched,
    )
