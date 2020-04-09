from pydantic import BaseModel, Field


class CountResponse(BaseModel):
    count: int = Field(
        ...,
        title="A number of matched items",
        description="A number of matched items with filters",
    )
