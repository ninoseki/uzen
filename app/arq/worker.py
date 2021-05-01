from tortoise import Tortoise

from app.arq.settings import get_redis_settings
from app.database import init_db
from app.tasks.preview import preview_task
from app.tasks.similarity import similarity_scan_task
from app.tasks.snapshot import enrich_snapshot_task, take_snapshot_task
from app.tasks.yara import yara_scan_task


async def startup(ctx: dict):
    await init_db()


async def shutdown(ctx: dict):
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
