import datetime
from typing import Optional, Union

from pydantic import AnyHttpUrl, BaseModel, IPvAnyAddress
from tortoise import fields
from tortoise.models import Model


class SnapshotBaseModel(BaseModel):
    """Base Pydantic model for Snapshot

    Note that this model doesn't have "id" and "created_at" fields.
    """

    url: AnyHttpUrl
    status: int
    hostname: str
    ip_address: IPvAnyAddress
    asn: str
    server: Optional[str]
    content_type: Optional[str]
    content_length: Optional[int]
    body: str
    sha256: str
    headers: dict
    screenshot: str
    whois: Optional[str]
    certificate: Optional[str]
    request: dict

    class Config:
        orm_mode = True


class SnapshotModel(SnapshotBaseModel):
    """Full Pydantic model for Snapshot

    """

    id: int
    created_at: datetime.datetime


class Snapshot(Model):
    """An ORM class for snapshots table

    """

    id = fields.IntField(pk=True)
    url = fields.TextField()
    status = fields.IntField()
    hostname = fields.TextField()
    ip_address = fields.CharField(max_length=255)
    asn = fields.TextField()
    server = fields.TextField(null=True)
    content_type = fields.TextField(null=True)
    content_length = fields.IntField(null=True)
    body = fields.TextField()
    sha256 = fields.CharField(max_length=64)
    headers = fields.JSONField()
    screenshot = fields.TextField()
    whois = fields.TextField(null=True)
    certificate = fields.TextField(null=True)
    request = fields.JSONField()
    created_at = fields.DatetimeField(auto_now_add=True)

    scripts: fields.ReverseRelation["Script"]

    def to_full_model(self) -> SnapshotModel:
        return SnapshotModel.from_orm(self)

    def to_base_model(self) -> SnapshotBaseModel:
        return SnapshotBaseModel.from_orm(self)

    def to_model(self) -> Union[SnapshotModel, SnapshotBaseModel]:
        if self.id is not None:
            return SnapshotModel.from_orm(self)
        else:
            return SnapshotBaseModel.from_orm(self)

    def to_dict(self) -> dict:
        model = self.to_model()
        return model.dict()

    def __str__(self) -> str:
        model = self.to_model()
        return model.json()

    class Meta:
        table = "snapshots"
