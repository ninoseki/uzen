from fastapi_utils.api_model import APIModel
from pydantic import Field


class BaseSearchResults(APIModel):
    total: int = Field(..., description="A total count of search results")
