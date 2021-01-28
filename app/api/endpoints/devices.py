from typing import List

from fastapi import APIRouter

from app import schemas
from app.utils.browser import get_devices as _get_devices

router = APIRouter()


@router.get(
    "/",
    response_model=List[schemas.Device],
    response_description="Returns a list of devices",
    summary="Get a list of devices",
    description="Get a list of devices supported to use",
)
def get_devices() -> List[schemas.Device]:
    return _get_devices()
