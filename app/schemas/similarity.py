from datetime import date, datetime
from typing import Dict, Optional, Union

from pydantic import Field, validator

from app.schemas.base import APIModel


class SimilarityScanPayload(APIModel):
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


class SimilarityScanPayloadWithSearchOptions(SimilarityScanPayload):
    """Similarity scan payload with search options"""

    size: Optional[int] = Field(None)
    offset: Optional[int] = Field(None)
    filters: Dict[str, Union[str, int, date, datetime, None]] = Field(...)
