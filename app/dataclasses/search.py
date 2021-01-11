from dataclasses import dataclass
from typing import List, Type, Union
from uuid import UUID

from pydantic import BaseModel
from tortoise.models import Model


@dataclass
class SearchResults:
    total: int
    results: Union[List[Type[Model]], List[Type[BaseModel]], List[dict], List[UUID]]
