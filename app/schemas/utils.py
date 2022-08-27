from pydantic import BaseModel, Field


class Count(BaseModel):
    """Count"""

    count: int = Field(
        ...,
        description="A Total count of items",
    )
