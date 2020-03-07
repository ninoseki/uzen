from typing import Optional
from urllib.parse import urlparse
import ssl
from OpenSSL import crypto


class Certificate:
    @staticmethod
    def load_and_dump_from_url(url: str) -> Optional[str]:
        """Load and dump a certficate as a string from a URL

        Arguments:
            url {str} -- A URL of a website

        Returns:
            Optional[str] -- A certificate as a string, returns None if it is not an HTTPS website
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return None

        hostname = parsed.netloc
        try:
            cert_pem = ssl.get_server_certificate((hostname, 443))
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
            dump = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)
            return dump.decode(encoding="utf-8")
        except (ssl.SSLError, ValueError):
            return None
