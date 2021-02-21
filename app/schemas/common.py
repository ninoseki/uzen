import yara
from fastapi_utils.api_model import APIModel
from pydantic import Field, validator

from app.schemas.types import TargetTypes


class Target(APIModel):
    target: TargetTypes = Field(
        "html",
        title="Target",
        description="A target field to scan (html, certificate, script or whois)",
    )


class Source(APIModel):
    source: str = Field(
        ...,
        title="YARA rule",
        description="String containing the YARA rule code",
        min_length=1,
    )

    @validator("source")
    def source_compilable(cls, v):
        try:
            yara.compile(source=v)
        except yara.Error as e:
            raise ValueError(f"YARA compile error: {str(e)}")
        return v
