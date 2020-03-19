from typing import List

from pydantic import AnyHttpUrl, BaseModel, Field

from uzen.models.dns_records import DnsRecordBaseModel
from uzen.models.scripts import ScriptBaseModel
from uzen.models.snapshots import BasicSnapshotModel


class ScanPayload(BaseModel):
    source: str = Field(
        None, title="YARA rule", description="String containing the rules code"
    )
    target: str = Field(
        "body",
        title="Target to scan",
        description="Target field to scan (body, whois or certificate)",
    )


class OneshotPayload(ScanPayload):
    url: AnyHttpUrl


class OneshotResponse(BaseModel):
    snapshot: BasicSnapshotModel = Field(
        None,
        title="Snapshot model",
        description="Snapshot model without id & created_at fields",
    )
    scripts: List[ScriptBaseModel] = Field(
        None,
        title="Script model",
        description="Script model without id & created_at fields",
    )
    dnsRecords: List[DnsRecordBaseModel] = Field(
        None,
        title="DNS record model",
        description="DNS record model without id & created_at fields",
    )
    matched: bool = Field(
        None, title="whether matched or not", description="whether matched or not"
    )
