from pydantic import Field

from app.schemas.base import APIModel


class Screenshot(APIModel):
    data: bytes = Field(..., description="PNG data")
