from humps import camelize
from pydantic import BaseModel, Field

from app.types import ULID


class APIModel(BaseModel):
    class Config:
        orm_mode = True
        alias_generator = camelize
        allow_population_by_field_name = True


class AbstractBaseModel(APIModel):
    id: ULID = Field(...)


class AbstractParentResourceModel(AbstractBaseModel):
    file_id: str = Field(..., title="SHA256", alias="sha256")


class AbstractResourceModel(APIModel):
    id: str = Field(..., title="ID", description="A SHA256 hash of the content")
    content: str = Field(...)
