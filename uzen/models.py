from tortoise import fields
from tortoise.models import Model
import json


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
    created_at = fields.DatetimeField(auto_now_add=True)

    def to_dict(self) -> dict:
        return dict(
            id=self.id,
            url=self.url,
            status=self.status,
            hostname=self.hostname,
            ip_address=self.ip_address,
            asn=self.asn,
            server=self.server,
            content_type=self.content_type,
            content_length=self.content_length,
            headers=self.headers,
            body=self.body,
            sha256=self.sha256,
            screenshot=self.screenshot,
            created_at=self.created_at.isoformat() if self.created_at else None,
        )

    def __str__(self) -> str:
        return json.dumps(self.to_dict())

    class Meta:
        table = "snapshots"
