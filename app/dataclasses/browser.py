from dataclasses import dataclass
from typing import Optional


@dataclass
class BrowsingResult:
    url: str
    status: int
    user_agent: str
    html: str
    headers: dict
    browser: str
    screenshot: Optional[bytes]
