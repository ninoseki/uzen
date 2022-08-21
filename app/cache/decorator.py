from aiocache import Cache
from aiocache.base import SENTINEL
from aiocache.decorators import cached as _cached
from aiocache.serializers import PickleSerializer

from app.core import settings
from app.core.datastructures import DatabaseURL

from .key_builder import default_key_builder


class cached(_cached):
    def __init__(
        self,
        ttl=SENTINEL,
        key_builder=default_key_builder,
        cache=Cache.REDIS,
        serializer=PickleSerializer(),
        plugins=None,
        alias=None,
        noself=False,
        namespace: str = settings.REDIS_CACHE_NAMESPACE,
        redis_url: DatabaseURL = settings.REDIS_CACHE_URL,
        **kwargs,
    ):
        if cache == Cache.REDIS:
            super().__init__(
                ttl=ttl,
                key=None,
                key_builder=key_builder,
                noself=noself,
                alias=alias,
                cache=cache,
                serializer=serializer,
                plugins=plugins,
                namespace=namespace,
                endpoint=redis_url.hostname,
                port=redis_url.port,
                password=redis_url.password,
                **kwargs,
            )
            return None

        super().__init__(
            ttl=ttl,
            key=None,
            key_builder=key_builder,
            noself=noself,
            alias=alias,
            cache=cache,
            serializer=serializer,
            plugins=plugins,
            namespace=namespace,
            **kwargs,
        )
