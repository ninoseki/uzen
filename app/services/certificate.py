import ssl
from typing import Optional
from urllib.parse import urlparse

from OpenSSL import crypto

from app import dataclasses


class Certificate:
    @staticmethod
    def load_from_url(url: str) -> Optional[dataclasses.Certificate]:
        """Load certficate from URL

        Arguments:
            url {str} -- A URL of a website

        Returns:
            Optional[dataclasses.Certificate] -- A certificate
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return None

        hostname = parsed.netloc
        try:
            cert_pem = ssl.get_server_certificate((hostname, 443))
            cert: crypto.X509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

            text: str = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode()
            fingerprint: str = cert.digest("sha256").decode().replace(":", "").lower()

            return dataclasses.Certificate(text=text, fingerprint=fingerprint)
        except (ssl.SSLError, ValueError):
            return None
