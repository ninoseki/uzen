from arq.connections import RedisSettings

from app.core import settings


def get_redis_settings() -> RedisSettings:
    return RedisSettings(
        host=settings.REDIS_URL.hostname,
        port=settings.REDIS_URL.port,
        password=settings.REDIS_URL.password,
    )
