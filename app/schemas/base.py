from uuid import UUID

from humps import camelize
from pydantic import BaseModel, Field


class APIModel(BaseModel):
    class Config:
        orm_mode = True
        alias_generator = camelize
        allow_population_by_field_name = True


class AbstractBaseModel(APIModel):
    id: UUID = Field(...)


class AbstractParentResourceModel(AbstractBaseModel):
    file_id: str = Field(..., title="SHA256", alias="sha256")


class AbstractResourceModel(APIModel):
    id: str = Field(..., title="ID", description="A SHA256 hash of the content")
    content: str = Field(...)
