import whois
from typing import Optional


class Whois:
    @staticmethod
    def whois(hostname: str) -> Optional[str]:
        try:
            w = whois.whois(hostname)
        except whois.parser.PywhoisError:
            return None

        return w.text
