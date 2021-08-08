from typing import Optional, Union
from uuid import UUID

from app import models, schemas
from app.api.dependencies.arq import get_arq_redis_with_context
from app.arq.constants import ENRICH_SNAPSHOT_TASK_NAME
from app.arq.tasks.classes.abstract import AbstractAsyncTask
from app.arq.tasks.classes.enrichment import EnrichmentTasks
from app.arq.tasks.classes.match import MatchingTask
from app.arq.tasks.classes.screenshot import UploadScrenshotTask
from app.core.exceptions import TakeSnapshotError
from app.services.browser import Browser


class UpdateProcessingTask(AbstractAsyncTask):
    def __init__(self, snapshot: models.Snapshot):
        self.snapshot = snapshot

    async def _process(self) -> None:
        self.snapshot.processing = False
        await self.snapshot.save()

    @classmethod
    async def process(cls, snapshot: models.Snapshot) -> None:
        instance = cls(snapshot)
        return await instance.safe_process()


async def enrich_snapshot_task(
    ctx: dict, snapshot: models.Snapshot
) -> schemas.JobResultWrapper:
    await EnrichmentTasks.process(snapshot)
    await MatchingTask.process(snapshot)
    await UpdateProcessingTask.process(snapshot)
    return schemas.JobResultWrapper(result={"snapshot_id": snapshot.id}, error=None)


async def take_snapshot_task(
    ctx: dict,
    payload: schemas.CreateSnapshotPayload,
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

    id: Optional[str] = ctx.get("job_id")
    snapshot = await models.Snapshot.save_snapshot(
        wrapper, id=id, api_key=api_key, tag_names=payload.tags
    )

    # upload screenshot
    if wrapper.screenshot is not None:
        UploadScrenshotTask.process(uuid=snapshot.id, screenshot=wrapper.screenshot)

    async with get_arq_redis_with_context() as arq_redis:
        await arq_redis.enqueue_job(ENRICH_SNAPSHOT_TASK_NAME, snapshot)

    return schemas.JobResultWrapper(result={"snapshot_id": snapshot.id}, error=None)
