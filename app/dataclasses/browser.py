from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from app.types import WaitUntilType

from .har import HAR

if TYPE_CHECKING:
    from app import models


@dataclass
class BrowserOptions:
    timeout: int = 30000
    headers: Dict[str, str] = field(default_factory=lambda: {})
    enable_har: bool = False
    ignore_https_errors: bool = False
    device_name: Optional[str] = None
    wait_until: WaitUntilType = "load"


@dataclass
class Snapshot:
    url: str
    status: int
    html: str
    options: BrowserOptions
    response_headers: Dict[str, Any]
    request_headers: Dict[str, Any]
    screenshot: Optional[bytes] = None
    har: Optional[HAR] = None


@dataclass
class ScriptFile:
    """Script with file"""

    script: "models.Script"
    file: "models.File"


@dataclass
class StylesheetFile:
    """Stylesheet with file"""

    stylesheet: "models.Stylesheet"
    file: "models.File"


@dataclass
class SnapshotModelWrapper:
    """Snapshot model and related models"""

    snapshot: "models.Snapshot"
    html: "models.HTML"
    whois: Optional["models.Whois"] = None
    certificate: Optional["models.Certificate"] = None
    screenshot: Optional[bytes] = None
    har: Optional["models.HAR"] = None
    script_files: List[ScriptFile] = field(default_factory=lambda: [])
    stylesheet_files: List[StylesheetFile] = field(default_factory=lambda: [])
