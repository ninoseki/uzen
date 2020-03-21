from pydantic import AnyHttpUrl, BaseModel
import datetime


class BaseScript(BaseModel):
    """Base Pydantic model for Script

    Note that this model doesn't have "id" and "created_at" fields.
    """

    url: AnyHttpUrl
    content: str
    sha256: str

    class Config:
        orm_mode = True


class Script(BaseScript):
    """Full Pydantic model for Snapshot"""

    id: int
    created_at: datetime.datetime
