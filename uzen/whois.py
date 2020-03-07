import whois
from typing import Optional


class Whois:
    @staticmethod
    def whois(hostname: str) -> Optional[str]:
        """Perform Whois lookup

        Arguments:
            hostname {str} -- Hostname

        Returns:
            Optional[str] -- Whois response as a string, returns None if an error occurs
        """
        try:
            w = whois.whois(hostname)
        except whois.parser.PywhoisError:
            return None

        return w.text
