import yara
from fastapi_utils.api_model import APIModel
from pydantic import Field, validator


class CountResponse(APIModel):
    count: int = Field(
        ...,
        title="A number of matched items",
        description="A number of matched items with filters",
    )


class Target(APIModel):
    target: str = Field(
        "body",
        title="Target",
        description="A target field to scan (body, certificate, script or whois)",
    )

    @validator("target")
    def target_types(cls, v):
        if v not in ["body", "certificate", "script", "whois"]:
            raise ValueError("Target must be any of body, certificate, script or whois")
        return v


class Source(APIModel):
    source: str = Field(
        ..., title="YARA rule", description="String containing the rules code",
    )

    @validator("source")
    def source_compilable(cls, v):
        try:
            yara.compile(source=v)
        except yara.Error as e:
            raise ValueError(f"YARA compile error: {str(e)}")
        return v
