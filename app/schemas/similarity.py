from functools import lru_cache
from typing import List, Optional

from pydantic import Field, validator

from app.schemas.base import APIModel
from app.schemas.snapshot import PlainSnapshot, SnapshotSearchFilters


class SimilarityScan(APIModel):
    """Similarity scan payload"""

    html: str = Field(...)
    threshold: Optional[float] = Field(None)
    exclude_hostname: Optional[str] = Field(None, description="Hostname to exclude")
    exclude_ip_address: Optional[str] = Field(None, description="IP address to exclude")

    @validator("threshold")
    def threshold_value(cls, v: Optional[float]):
        if v is None:
            return v

        if v < 0.0:
            raise ValueError("Threshold should be greather than 0.0")

        if v > 1.0:
            raise ValueError("Threshold should be smaller than 1.0")

        return v


class SimilarityScanWithSearchOptions(SimilarityScan):
    """Similarity scan payload with search options"""

    size: Optional[int] = Field(None)
    offset: Optional[int] = Field(None)
    filters: SnapshotSearchFilters = Field(...)


class SimilarityScanResult(PlainSnapshot):
    """Similarity scan result + snapshot"""

    similarity: float = Field(...)

    @classmethod
    @lru_cache(maxsize=1)
    def field_keys(cls) -> List[str]:
        keys = list(cls.__fields__.keys())

        for non_db_key in ["similarity", "tags"]:
            if non_db_key in keys:
                keys.remove(non_db_key)

        return keys
