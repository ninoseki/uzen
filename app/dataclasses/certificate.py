import datetime
from dataclasses import dataclass
from typing import Optional


@dataclass
class Certificate:
    fingerprint: str
    text: str
    issuer: str
    subject: str
    not_after: Optional[datetime.datetime] = None
    not_before: Optional[datetime.datetime] = None
