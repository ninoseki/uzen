from typing import List, Optional, cast

import httpx

from app.models.snapshots import Snapshot
from app.schemas.utils import ScriptFile, SnapshotResult
from app.services.certificate import Certificate
from app.services.utils import (
    calculate_sha256,
    get_asn_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)
from app.services.whois import Whois
from app.tasks.scripts import ScriptTask

DEFAULT_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
DEFAULT_AL = "en-US"
DEFAULT_REFERER = ""


class FakeBrowser:
    @staticmethod
    async def take_snapshot(
        url: str,
        accept_language: Optional[str] = None,
        host: Optional[str] = None,
        ignore_https_errors: bool = False,
        referer: Optional[str] = None,
        timeout: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> SnapshotResult:
        """Take a snapshot of a website by httpx

        Arguments:
            url {str} -- A URL of a website

        Keyword Arguments:
            accept_language {Optional[str]} -- Accept-language header to use (default: {None})
            host {Optional[str]} -- Host header to use (default: {None})
            ignore_https_errors {bool} -- Whether to ignore HTTPS errors (default: {False})
            referer {Optional[str]} -- Referer header to use (default: {None})
            timeout {Optional[int]} -- Maximum time to wait for in seconds (default: {None})
            user_agent {Optional[str]} -- User-agent header to use (default: {None})

        Returns:
            SnapshotResult
        """
        submitted_url: str = url
        verify = not ignore_https_errors

        try:
            # default timeout = 30 seconds
            timeout = int(timeout / 1000) if timeout is not None else 30

            headers = {
                "user-agent": user_agent or DEFAULT_UA,
                "accept-language": accept_language or DEFAULT_AL,
                "referer": referer or DEFAULT_REFERER,
            }
            if host is not None:
                headers["host"] = host

            async with httpx.AsyncClient(verify=verify) as client:
                res = await client.get(
                    url, headers=headers, timeout=timeout, allow_redirects=True,
                )

                request = {
                    "accept_language": accept_language,
                    "browser": "httpx",
                    "host": host,
                    "ignore_https_errors": ignore_https_errors,
                    "referer": referer,
                    "timeout": timeout,
                    "user_agent": user_agent,
                }

                url = str(res.url)
                status = res.status_code
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
        asn = get_asn_by_ip_address(ip_address) or ""
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
        )

        # get script files
        script_files = cast(
            List[ScriptFile], await ScriptTask.process(snapshot, insert_to_db=False)
        )

        return SnapshotResult(
            screenshot=None, snapshot=snapshot, script_files=script_files
        )
