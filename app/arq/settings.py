from aioredis.connection import parse_url
from arq.connections import RedisSettings

from app.core import settings


def get_redis_settings() -> RedisSettings:
    address, options = parse_url(settings.REDIS_URL)
    host, port = address
    password = options.get("password")

    return RedisSettings(host=host, port=port, password=password)
