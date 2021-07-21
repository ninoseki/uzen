from typing import Union
from uuid import UUID

from fastapi import BackgroundTasks, Security
from fastapi.exceptions import HTTPException
from fastapi.security import APIKeyHeader
from tortoise.exceptions import DoesNotExist

from app import models
from app.core import settings

api_key_header = APIKeyHeader(name="api-key", scheme_name="API key header")

secret_api_key_header = APIKeyHeader(
    name="secret-api-key", scheme_name="Secret API key header"
)


async def update_api_key_usage(api_key: Union[str, UUID]):
    try:
        key = await models.APIKey.get_by_id(api_key)
    except DoesNotExist:
        return

    await key.update_usage()


async def verify_api_key(
    background_tasks: BackgroundTasks, api_key: str = Security(api_key_header)
) -> None:
    is_active_key = await models.APIKey.is_active_key(api_key)
    if not is_active_key:
        raise HTTPException(status_code=403, detail="API-Key header invalid")

    background_tasks.add_task(update_api_key_usage, api_key)


def verify_secret_api_key(
    secret_api_key: str = Security(secret_api_key_header),
) -> None:
    if secret_api_key != settings.SECRET_API_KEY:
        raise HTTPException(status_code=403, detail="Secret-API-Key header invalid")
