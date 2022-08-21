from typing import Any, Callable, Coroutine

from fastapi import FastAPI
from tortoise import Tortoise

import app.database


def create_start_app_handler(
    app_: FastAPI,
) -> Callable[[], Coroutine[Any, Any, None]]:
    async def start_app() -> None:
        # initialize Tortoise ORM
        await app.database.init_db()

    return start_app


def create_stop_app_handler(
    app_: FastAPI,
) -> Callable[[], Coroutine[Any, Any, None]]:
    async def stop_app() -> None:
        # close DB connections
        await Tortoise.close_connections()

    return stop_app
