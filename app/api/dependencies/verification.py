from fastapi import Header
from fastapi.exceptions import HTTPException

from app.core import settings


async def verify_api_key(api_key: str = Header(...)):
    if api_key != settings.GLOBAL_API_KEY:
        raise HTTPException(status_code=400, detail="API-Key header invalid")
