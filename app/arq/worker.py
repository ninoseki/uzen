from tortoise import Tortoise

from app.arq.settings import get_redis_settings
from app.arq.tasks.preview import preview_task
from app.arq.tasks.similarity import similarity_scan_task
from app.arq.tasks.snapshot import enrich_snapshot_task, take_snapshot_task
from app.arq.tasks.yara import yara_scan_task
from app.database import init_db


async def startup(ctx: dict) -> None:
    await init_db()


async def shutdown(ctx: dict) -> None:
    await Tortoise.close_connections()


class ArqWorkerSettings:
    functions = [
        enrich_snapshot_task,
        preview_task,
        similarity_scan_task,
        take_snapshot_task,
        yara_scan_task,
    ]
    redis_settings = get_redis_settings()

    on_startup = startup
    on_shutdown = shutdown
