from fastapi import FastAPI
from tortoise import Tortoise
from typing import Callable

from uzen.core import settings


def create_start_app_handler(app: FastAPI) -> Callable:
    async def start_app() -> None:
        await Tortoise.init(
            db_url=settings.DATABASE_URL,
            modules={
                "models": settings.APP_MODELS
            }
        )
        await Tortoise.generate_schemas()

    return start_app


def create_stop_app_handler(app: FastAPI) -> Callable:
    async def stop_app() -> None:
        await Tortoise.close_connections()

    return stop_app
