from typing import Any, Callable, Coroutine, Union

import aioredis
from fastapi import FastAPI
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from loguru import logger
from tortoise import Tortoise

from app.cache.backend import InMemoryBackend
from app.core import settings
from app.database import init_db


def create_start_app_handler(
    app: FastAPI,
) -> Callable[[], Coroutine[Any, Any, None]]:
    async def start_app() -> None:
        # initialize Tortoise ORM
        await init_db()

        # initialize FastAPI cache
        backend: Union[InMemoryBackend, RedisBackend] = InMemoryBackend()
        if settings.REDIS_URL != "" and settings.TESTING is False:
            try:
                redis = await aioredis.create_redis_pool(settings.REDIS_URL)
                backend = RedisBackend(redis)
            except ConnectionRefusedError as e:
                logger.error(f"Failed to connect to Redis: {settings.REDIS_URL}")
                logger.exception(e)

        FastAPICache.init(backend, prefix="fastapi-cache")

    return start_app


def create_stop_app_handler(
    app: FastAPI,
) -> Callable[[], Coroutine[Any, Any, None]]:
    async def stop_app() -> None:
        # close DB connections
        await Tortoise.close_connections()

    return stop_app
