from pydantic import BaseModel, Field


class CountResponse(BaseModel):
    count: int = Field(
        ..., title="Count", description="Total count of existing items",
    )
