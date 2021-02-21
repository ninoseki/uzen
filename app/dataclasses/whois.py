import datetime
from dataclasses import dataclass
from typing import Optional


@dataclass
class Whois:
    content: str

    created: Optional[datetime.datetime] = None
    updated: Optional[datetime.datetime] = None
    expires: Optional[datetime.datetime] = None

    registrar: Optional[str] = None
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
