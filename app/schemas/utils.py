from pydantic import BaseModel, Field


class CountResponse(BaseModel):
    """Count"""

    count: int = Field(
        ...,
        description="A Total count of items",
    )
