from uuid import UUID

from fastapi_utils.api_model import APIModel
from pydantic import Field


class AbstractBaseModel(APIModel):
    id: UUID = Field(...)


class AbstractParentResourceModel(AbstractBaseModel):
    file_id: str = Field(..., title="SHA256", alias="sha256")


class AbstractResourceModel(APIModel):
    id: str = Field(..., title="ID", description="A SHA256 hash of the content")
    content: str = Field(...)
