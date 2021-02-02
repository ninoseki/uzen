from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dataclasses_json import config, dataclass_json
from stringcase import camelcase

from app.types import WaitUntilType


@dataclass
class BrowsingOptions:
    timeout: int = 30000
    headers: Dict[str, str] = field(default_factory=lambda: {})
    enable_har: bool = False
    ignore_https_errors: bool = False
    device_name: Optional[str] = None
    wait_until: WaitUntilType = "load"


@dataclass_json(letter_case=camelcase)
@dataclass
class Response:
    url: str
    status: int
    status_text: str
    headers: dict
    mime_type: str
    connection_reused: bool
    connection_id: int
    encoded_data_length: int
    security_state: str
    response_time: Optional[float] = None
    request_headers: Optional[dict] = None
    request_headers_text: Optional[str] = None
    remote_ip_address: Optional[str] = field(
        default=None, metadata=config(field_name="remoteIPAddress")
    )
    remote_port: Optional[int] = None
    from_disk_cache: Optional[bool] = None
    from_service_worker: Optional[bool] = None
    from_prefetch_cache: Optional[bool] = None
    timing: Optional[Dict[str, float]] = None
    protocol: Optional[str] = None
    headers_text: Optional[str] = None


@dataclass_json(letter_case=camelcase)
@dataclass
class ResponseReceivedEvent:
    request_id: str
    loader_id: str
    timestamp: float
    type: str
    response: Response
    frame_id: str


@dataclass
class BrowsingResult:
    url: str
    status: int
    html: str
    response_headers: dict
    request_headers: dict
    options: BrowsingOptions
    screenshot: Optional[bytes] = None
    response_received_events: List[ResponseReceivedEvent] = field(
        default_factory=lambda: []
    )
