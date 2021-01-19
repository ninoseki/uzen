from fastapi_utils.api_model import APIModel
from pydantic import Field


class Screenshot(APIModel):
    data: bytes = Field(..., title="Data", description="Png data")
