from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from playwright_har_tracer.dataclasses.har import Har

from app.types import WaitUntilType


@dataclass
class BrowsingOptions:
    timeout: int = 30000
    headers: Dict[str, str] = field(default_factory=lambda: {})
    enable_har: bool = False
    ignore_https_errors: bool = False
    device_name: Optional[str] = None
    wait_until: WaitUntilType = "load"


@dataclass
class BrowsingResult:
    url: str
    status: int
    html: str
    options: BrowsingOptions
    response_headers: Dict[str, Any]
    request_headers: Dict[str, Any]
    screenshot: Optional[bytes] = None
    har: Optional[Har] = None
