from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Type, Union
from uuid import UUID

from pydantic import BaseModel
from tortoise.models import Model

if TYPE_CHECKING:
    from app import models


@dataclass
class HttpResource:
    """HTTP response resource"""

    url: str
    content: str
    content_type: Optional[str] = None


@dataclass
class Enrichments:
    """Classifications and DNS records"""

    classifications: List["models.Classification"]
    dns_records: List["models.DnsRecord"]


@dataclass
class SearchResults:
    """Search results with total"""

    results: Union[List[Type[Model]], List[Type[BaseModel]], List[dict], List[UUID]]
    total: int
