from contextlib import asynccontextmanager
from typing import AsyncGenerator

from arq import ArqRedis, create_pool

from app.arq.settings import get_redis_settings


@asynccontextmanager
async def get_arq_redis_with_context() -> AsyncGenerator[ArqRedis, None]:
    redis: ArqRedis = await create_pool(settings_=get_redis_settings())

    try:
        yield redis
    finally:
        redis.close()
        await redis.wait_closed()


async def get_arq_redis():
    async with get_arq_redis_with_context() as arq_redis:
        yield arq_redis
