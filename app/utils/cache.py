from app.core import settings

if not settings.TESTING:
    from fastapi_cache.decorator import cache
else:
    from functools import wraps

    def cache(*args, **kwargs):
        def wrapper(func):
            @wraps(func)
            async def inner(*args, **kwargs):
                return await func(*args, **kwargs)

            return inner

        return wrapper


__all__ = ["cache"]
