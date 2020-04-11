from typing import List

import yara
from fastapi import APIRouter, Depends, HTTPException

from uzen.api.dependencies.snapshots import search_filters
from uzen.api.jobs import run_enrhichment_jobs
from uzen.schemas.yara import (
    OneshotPayload,
    OneshotResponse,
    ScanPayload,
    ScanResult,
)
from uzen.services.snapshot import TakeSnapshotError, take_snapshot
from uzen.services.yara_scanner import YaraScanner

router = APIRouter()


@router.post(
    "/scan",
    response_model=List[ScanResult],
    response_description="Returns a list of matched snapshots",
    summary="Perform YARA scans against snapshtos",
    description="Perform YARA scans against snapshtos (which can be narrowed down by filters)",
)
async def scan(
    payload: ScanPayload, filters: dict = Depends(search_filters)
) -> List[ScanResult]:
    yara_scanner = YaraScanner(payload.source)
    results = await yara_scanner.scan_snapshots(payload.target, filters)
    return results


@router.post(
    "/oneshot",
    response_model=OneshotResponse,
    response_description="Returns a snapshot and a matching result",
    summary="Perform a YARA scan against a website",
    description="Perform oneshot YARA scan against a website",
)
async def oneshot(payload: OneshotPayload) -> OneshotResponse:
    yara_scanner = YaraScanner(payload.source)
    try:
        snapshot = await take_snapshot(
            url=payload.url,
            accept_language=payload.accept_language,
            ignore_https_errors=payload.ignore_https_errors,
            referer=payload.referer,
            timeout=payload.timeout,
            user_agent=payload.user_agent,
        )
    except TakeSnapshotError as e:
        raise HTTPException(status_code=500, detail=str(e))

    results = await run_enrhichment_jobs(snapshot, insert_to_db=False)
    snapshot.scripts = [script.to_model() for script in results.scripts]
    snapshot.dns_records = [record.to_model() for record in results.dns_records]
    snapshot.classifications = [
        classification.to_model() for classification in results.classifications
    ]

    matched = False
    matches = []
    if payload.target == "script":
        for script in results.scripts:
            matches = yara_scanner.match(script.content)
            if len(matches) > 0:
                matched = True
                break
    else:
        data = snapshot.to_dict().get(payload.target, "")
        matches = yara_scanner.match(data)
        matched = True if len(matches) > 0 else False

    return OneshotResponse(
        snapshot=snapshot.to_model(), matched=matched, matches=matches,
    )
