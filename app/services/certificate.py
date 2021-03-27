import datetime
import socket
import ssl
from typing import List, Optional, Tuple, cast
from urllib.parse import urlparse

from OpenSSL import crypto

from app import dataclasses


def asn1time_to_datetime(asn1: Optional[bytes]) -> Optional[datetime.datetime]:
    if asn1 is None:
        return None

    return datetime.datetime.strptime(asn1.decode(), "%Y%m%d%H%M%SZ")


def components_to_string(components: List[Tuple[bytes, bytes]]) -> str:
    return ",".join(f"/{name.decode()}={value.decode()}" for name, value in components)


def get_certification(hostname: str, port: int) -> crypto.X509:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as ssl_socket:
            peer_cert = cast(bytes, ssl_socket.getpeercert(True))
            pem_cert = ssl.DER_cert_to_PEM_cert(peer_cert)
            return crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)


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
        port = parsed.port or 443
        try:
            cert = get_certification(hostname, port)

            text: str = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode()
            fingerprint: str = cert.digest("sha256").decode().replace(":", "").lower()
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            not_after = cert.get_notAfter()
            not_before = cert.get_notBefore()

            return dataclasses.Certificate(
                text=text,
                fingerprint=fingerprint,
                subject=components_to_string(subject.get_components()),
                issuer=components_to_string(issuer.get_components()),
                not_after=asn1time_to_datetime(not_after),
                not_before=asn1time_to_datetime(not_before),
            )
        except (ssl.SSLError, ValueError):
            return None
