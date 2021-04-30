from app import models, schemas
from app.api.dependencies.arq import get_arq_redis_with_context
from app.arq.constants import enrich_snapshot_task_name
from app.core.exceptions import TakeSnapshotError
from app.services.browser import Browser
from app.tasks import AbstractAsyncTask
from app.tasks.enrichment import EnrichmentTasks
from app.tasks.match import MatchingTask
from app.tasks.screenshot import UploadScrenshotTask


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
    ctx: dict, payload: schemas.CreateSnapshotPayload
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
        result = await browser.take_snapshot(payload.url)
    except TakeSnapshotError as e:
        return schemas.JobResultWrapper(result=None, error=str(e))

    snapshot = await models.Snapshot.save_snapshot_result(result)

    # upload screenshot
    if result.screenshot is not None:
        UploadScrenshotTask.process(uuid=snapshot.id, screenshot=result.screenshot)

    async with get_arq_redis_with_context() as arq_redis:
        await arq_redis.enqueue_job(enrich_snapshot_task_name, snapshot)

    return schemas.JobResultWrapper(result={"snapshot_id": snapshot.id}, error=None)
