from typing import Any, Callable, Coroutine

from fastapi import FastAPI
from tortoise import Tortoise

from app.core import settings


def create_start_app_handler(
    app: FastAPI,
) -> Callable[[], Coroutine[Any, Any, None]]:
    async def start_app() -> None:
        await Tortoise.init(
            db_url=settings.DATABASE_URL, modules={"models": settings.APP_MODELS}
        )
        await Tortoise.generate_schemas()

    return start_app


def create_stop_app_handler(
    app: FastAPI,
) -> Callable[[], Coroutine[Any, Any, None]]:
    async def stop_app() -> None:
        await Tortoise.close_connections()

    return stop_app
