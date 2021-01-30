from dataclasses import dataclass


@dataclass
class Certificate:
    fingerprint: str
    text: str
