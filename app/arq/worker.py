from typing import Optional, Sequence, Union

from arq.connections import RedisSettings
from arq.typing import StartupShutdown, WorkerCoroutine
from arq.worker import Function, func
from tortoise import Tortoise

from app.arq.constants import (
    ENRICH_SNAPSHOT_TASK_NAME,
    PREVIEW_TASK_NAME,
    SIMILARITY_SCAN_TASK_NAME,
    SNAPSHOT_TASK_NAME,
    YARA_SCAN_TASK_NAME,
)
from app.arq.settings import get_redis_settings
from app.arq.tasks.preview import preview_task
from app.arq.tasks.similarity import similarity_scan_task
from app.arq.tasks.snapshot import enrich_snapshot_task, take_snapshot_task
from app.arq.tasks.yara import yara_scan_task
from app.cache.constants import ONE_DAY, ONE_HOUR
from app.core import settings
from app.database import init_db
from app.sentry import init_sentry


async def startup(ctx: dict) -> None:
    init_sentry()
    await init_db()


async def shutdown(ctx: dict) -> None:
    await Tortoise.close_connections()


class ArqWorkerSettings:
    # default timeout = 300s, keep_result = 3600s
    functions: Sequence[Union[Function, WorkerCoroutine]] = [
        func(enrich_snapshot_task, name=ENRICH_SNAPSHOT_TASK_NAME),
        func(preview_task, name=PREVIEW_TASK_NAME),
        func(
            similarity_scan_task,
            name=SIMILARITY_SCAN_TASK_NAME,
            timeout=ONE_HOUR,
            keep_result=ONE_DAY,
        ),
        func(take_snapshot_task, name=SNAPSHOT_TASK_NAME),
        func(
            yara_scan_task,
            name=YARA_SCAN_TASK_NAME,
            timeout=ONE_HOUR,
            keep_result=ONE_DAY,
        ),
    ]
    redis_settings: RedisSettings = get_redis_settings()

    max_jobs: int = settings.ARQ_MAX_JOBS

    on_startup: Optional[StartupShutdown] = startup
    on_shutdown: Optional[StartupShutdown] = shutdown
