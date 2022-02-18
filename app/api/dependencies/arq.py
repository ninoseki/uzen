from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from arq import ArqRedis, create_pool

from app.arq.settings import get_redis_settings


@asynccontextmanager
async def get_arq_redis_with_context() -> AsyncGenerator[ArqRedis, None]:
    redis: Optional[ArqRedis] = None

    try:
        redis = await create_pool(settings_=get_redis_settings())
        yield redis
    finally:
        if redis is not None:
            redis.close()
            await redis.wait_closed()


async def get_arq_redis():
    async with get_arq_redis_with_context() as arq_redis:
        yield arq_redis
