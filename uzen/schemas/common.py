import yara
from pydantic import BaseModel, Field, validator


class CountResponse(BaseModel):
    count: int = Field(
        ...,
        title="A number of matched items",
        description="A number of matched items with filters",
    )


class Target(BaseModel):
    target: str = Field(
        "body",
        title="Target to scan",
        description="Target field to scan (body, whois or certificate)",
    )

    @validator("target")
    def target_types(cls, v):
        if v not in ["body", "certificate", "script", "whois"]:
            raise ValueError("Target must be any of body, certificate, script or whois")
        return v


class Source(BaseModel):
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
