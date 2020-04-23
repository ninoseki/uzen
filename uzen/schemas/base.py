from uuid import UUID

from fastapi_utils.api_model import APIModel


class AbstractBaseModel(APIModel):
    """Full Pydantic model for Classification"""

    id: UUID
