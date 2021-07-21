from typing import Any, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.api.dependencies.verification import verify_secret_api_key

router = APIRouter()


async def _get_api_key(api_key: Union[str, UUID]) -> models.APIKey:
    try:
        key = await models.APIKey.get_by_id(api_key)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"API key:{api_key} is not found")

    return key


@router.get(
    "/new",
    response_model=schemas.APIKey,
    summary="Create a new API key",
    status_code=201,
)
async def create_new_api_key(_: Any = Depends(verify_secret_api_key)) -> schemas.APIKey:
    key = models.APIKey()
    await key.save()

    return schemas.APIKey.from_orm(key)


@router.post(
    "/revoke",
    summary="Revoke an API key",
    status_code=204,
)
async def revoke_api_key(
    payload: schemas.RevokeOrActivateAPIKey, _: Any = Depends(verify_secret_api_key)
) -> schemas.APIKey:
    api_key = await _get_api_key(payload.api_key)
    await api_key.revoke()
    return {}


@router.post(
    "/activate",
    summary="Activate an API key",
    status_code=204,
)
async def activate_api_key(
    payload: schemas.RevokeOrActivateAPIKey, _: Any = Depends(verify_secret_api_key)
) -> schemas.APIKey:
    api_key = await _get_api_key(payload.api_key)
    await api_key.activate()
    return {}


@router.post(
    "/status",
    response_model=schemas.APIKey,
    summary="Get a status of an API key",
)
async def get_api_key(
    payload: schemas.RevokeOrActivateAPIKey, _: Any = Depends(verify_secret_api_key)
) -> schemas.APIKey:
    api_key = await _get_api_key(payload.api_key)
    return schemas.APIKey.from_orm(api_key)
