from pydantic import Field

from app.schemas.base import APIModel


class BaseSearchResults(APIModel):
    total: int = Field(..., description="A total count of search results")
