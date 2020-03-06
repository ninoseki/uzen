from pydantic import BaseModel, HttpUrl
from tortoise import fields
from tortoise.models import Model
from typing import Optional
import datetime


class SnapshotModel(BaseModel):
    id: Optional[int]
    url: str
    status: int
    hostname: str
    ip_address: str
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
    created_at: Optional[datetime.datetime]

    class Config:
        orm_mode = True


class Snapshot(Model):
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
    created_at = fields.DatetimeField(auto_now_add=True)

    def to_pandantic_model(self) -> SnapshotModel:
        return SnapshotModel.from_orm(self)

    def to_dict(self) -> dict:
        model = self.to_pandantic_model()
        return model.dict()

    def __str__(self) -> str:
        model = self.to_pandantic_model()
        return model.json()

    class Meta:
        table = "snapshots"
