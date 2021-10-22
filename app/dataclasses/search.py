from dataclasses import dataclass
from typing import List, Type, Union

from pydantic import BaseModel
from tortoise.models import Model

from app import types


@dataclass
class SearchResults:
    total: int
    results: Union[
        List[Type[Model]], List[Type[BaseModel]], List[dict], List[types.ULID]
    ]
