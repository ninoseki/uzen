from pydantic import BaseModel, Field


class CountResponse(BaseModel):
    count: int = Field(
        None,
        title="A number of matched items",
        description="A number of matched items with filters",
    )
