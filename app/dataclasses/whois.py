from dataclasses import dataclass
from typing import Optional


@dataclass
class Whois:
    content: str

    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None

    registrar: Optional[str] = None
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
