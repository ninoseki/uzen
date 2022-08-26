from typing import Optional, Union, cast
from uuid import UUID

from arq.connections import ArqRedis

from app import models, schemas
from app.arq.constants import ENRICH_SNAPSHOT_TASK_NAME
from app.arq.tasks.helpers.enrichment import EnrichmentHelpers
from app.arq.tasks.helpers.match import MatchingHelper
from app.arq.tasks.helpers.screenshot import UploadScreenshotHelper
from app.arq.tasks.helpers.snapshot import UpdateProcessingHelper
from app.core.exceptions import TakeSnapshotError
from app.services.browser import Browser
from app.utils.ulid import get_ulid_str


async def enrich_snapshot_task(
    ctx_: dict, snapshot: models.Snapshot
) -> schemas.JobResultWrapper:
    await EnrichmentHelpers.process(snapshot)
    await MatchingHelper.process(snapshot)
    await UpdateProcessingHelper.process(snapshot)
    return schemas.JobResultWrapper(result={"snapshot_id": snapshot.id}, error=None)


async def take_snapshot_task(
    ctx: dict,
    payload: schemas.SnapshotCreate,
    api_key: Optional[Union[str, UUID]] = None,
) -> schemas.JobResultWrapper:
    ignore_https_error = payload.ignore_https_errors or False
    browser = Browser(
        enable_har=payload.enable_har,
        ignore_https_errors=ignore_https_error,
        timeout=payload.timeout,
        device_name=payload.device_name,
        headers=payload.headers,
        wait_until=payload.wait_until,
    )
    try:
        wrapper = await browser.take_snapshot(payload.url)
    except TakeSnapshotError as e:
        return schemas.JobResultWrapper(result=None, error=str(e))

    snapshot = await models.Snapshot.save_snapshot(
        wrapper, id=get_ulid_str(), api_key=api_key, tag_names=payload.tags
    )

    # upload screenshot
    if wrapper.screenshot is not None:
        await UploadScreenshotHelper.process(
            uuid=snapshot.id, screenshot=wrapper.screenshot
        )

    redis = cast(Optional[ArqRedis], ctx.get("redis"))
    if redis is not None:
        await redis.enqueue_job(ENRICH_SNAPSHOT_TASK_NAME, snapshot)

    return schemas.JobResultWrapper(result={"snapshot_id": snapshot.id}, error=None)
