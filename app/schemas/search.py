from fastapi_utils.api_model import APIModel
from pydantic import Field


class BaseSearchResults(APIModel):
    total: int = Field(..., title="total", description="Total count of search results")
