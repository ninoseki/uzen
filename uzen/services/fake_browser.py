from typing import Optional, cast
import httpx

from uzen.models.snapshots import Snapshot
from uzen.services.certificate import Certificate
from uzen.services.utils import (
    calculate_sha256,
    get_asn_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)
from uzen.services.whois import Whois

DEFAULT_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
DEFAULT_AL = "en-US"


class FakeBrowser:
    @staticmethod
    async def take_snapshot(
        url: str,
        user_agent: Optional[str] = None,
        timeout: Optional[int] = None,
        ignore_https_errors: bool = False,
        accept_language: Optional[str] = None,
    ) -> Snapshot:
        """Take a snapshot of a website by httpx

        Arguments:
            url {str} -- A URL of a website

        Keyword Arguments:
            user_agent {Optional[str]} -- User agent to use (default: {None})
            timeout {Optional[int]} -- Maximum time to wait for in seconds (default: {None})
            ignore_https_errors {bool} -- Whether to ignore HTTPS errors (default: {False})

        Returns:
            Snapshot -- Snapshot ORM instance
        """
        submitted_url: str = url

        try:
            # default timeout = 30 seconds
            timeout = int(timeout / 1000) if timeout is not None else 30
            client = httpx.AsyncClient()
            res = await client.get(
                url,
                headers={
                    "user-agent": user_agent or DEFAULT_UA,
                    "accept-language": accept_language or DEFAULT_AL,
                },
                timeout=timeout,
                allow_redirects=True,
            )

            request = {
                "browser": "httpx",
                "ignore_https_errors": ignore_https_errors,
                "timeout": timeout,
                "user_agent": user_agent or DEFAULT_UA,
                "accept_language": accept_language,
            }

            url = str(res.url)
            status = res.status_code
            screenshot = ""
            body = res.text
            sha256 = calculate_sha256(body)
            headers = {k.lower(): v for (k, v) in res.headers.items()}
        except httpx.HTTPError as e:
            raise (e)

        server = headers.get("server")
        content_type = headers.get("content-type")
        content_length = headers.get("content-length")

        hostname = cast(str, get_hostname_from_url(url))
        certificate = Certificate.load_and_dump_from_url(url)
        ip_address = cast(str, get_ip_address_by_hostname(hostname))
        asn = await get_asn_by_ip_address(ip_address)
        whois = Whois.whois(hostname)

        snapshot = Snapshot(
            url=url,
            submitted_url=submitted_url,
            status=status,
            body=body,
            sha256=sha256,
            headers=headers,
            hostname=hostname,
            ip_address=ip_address,
            asn=asn,
            server=server,
            content_length=content_length,
            content_type=content_type,
            whois=whois,
            certificate=certificate,
            request=request,
            screenshot=screenshot,
        )

        return snapshot
