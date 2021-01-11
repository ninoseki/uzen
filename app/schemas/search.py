from dataclasses import dataclass
from typing import List, Type, Union
from uuid import UUID

from fastapi_utils.api_model import APIModel
from pydantic import BaseModel, Field
from tortoise.models import Model


class BaseSearchResults(APIModel):
    total: int = Field(..., title="total", description="Total count of search results")


# TODO: Use Pydantic model instead of dataclass
@dataclass
class SearchResults:
    total: int
    results: Union[List[Type[Model]], List[Type[BaseModel]], List[dict], List[UUID]]
