from arq.connections import RedisSettings

from app.core import settings


def get_redis_settings() -> RedisSettings:
    return RedisSettings(
        host=settings.REDIS_URL.hostname or "localhost",
        port=settings.REDIS_URL.port or 6379,
        password=settings.REDIS_URL.password,
        conn_retries=settings.ARQ_REDIS_CONN_RETRIES,
        conn_timeout=settings.ARQ_REDIS_CONN_TIMEOUT,
        conn_retry_delay=settings.ARQ_REDIS_CONN_RETRY_DELAY,
    )
