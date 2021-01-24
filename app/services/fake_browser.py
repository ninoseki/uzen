from typing import List, Optional, cast

import httpx

from app import dataclasses, models
from app.dataclasses.browser import BrowsingResult
from app.services.certificate import Certificate
from app.services.whois import Whois
from app.tasks.script import ScriptTask
from app.utils.hash import calculate_sha256
from app.utils.network import (
    get_asn_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)

DEFAULT_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
DEFAULT_AL = "en-US"
DEFAULT_REFERER = ""


async def run_httpx(
    url: str,
    host: Optional[str] = None,
    accept_language: Optional[str] = None,
    ignore_https_errors: bool = False,
    referer: Optional[str] = None,
    timeout: Optional[int] = None,
    user_agent: Optional[str] = None,
) -> BrowsingResult:
    verify = not ignore_https_errors

    # default timeout = 30 seconds
    timeout = int(timeout / 1000) if timeout is not None else 30

    user_agent = user_agent or DEFAULT_UA

    headers = {
        "user-agent": user_agent,
        "accept-language": accept_language or DEFAULT_AL,
        "referer": referer or DEFAULT_REFERER,
    }
    if host is not None:
        headers["host"] = host

    async with httpx.AsyncClient(verify=verify) as client:
        res = await client.get(
            url, headers=headers, timeout=timeout, allow_redirects=True,
        )
        headers = {k.lower(): v for (k, v) in res.headers.items()}
        return BrowsingResult(
            url=str(res.url),
            status=res.status_code,
            screenshot=None,
            html=res.text,
            headers=headers,
            user_agent=user_agent,
            browser="httpx",
        )


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
    ) -> dataclasses.SnapshotResult:
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

        try:
            result = await run_httpx(
                url,
                host=host,
                accept_language=accept_language,
                referer=referer,
                timeout=timeout,
                ignore_https_errors=ignore_https_errors,
                user_agent=user_agent,
            )
        except httpx.HTTPError as e:
            raise (e)

        options = {
            "accept_language": accept_language,
            "browser": result.browser,
            "host": host,
            "ignore_https_errors": ignore_https_errors,
            "referer": referer,
            "timeout": timeout,
            "user_agent": result.user_agent,
        }

        headers = result.headers
        server = headers.get("server")
        content_type = headers.get("content-type")
        content_length = headers.get("content-length")

        url = result.url
        hostname = cast(str, get_hostname_from_url(url))
        ip_address = cast(str, get_ip_address_by_hostname(hostname))
        asn = get_asn_by_ip_address(ip_address) or ""

        certificate_content = Certificate.load_and_dump_from_url(url)
        whois_content = Whois.whois(hostname)

        snapshot = models.Snapshot(
            url=url,
            submitted_url=submitted_url,
            status=result.status,
            headers=headers,
            hostname=hostname,
            ip_address=ip_address,
            asn=asn,
            server=server,
            content_length=content_length,
            content_type=content_type,
            options=options,
        )
        html = models.HTML(id=calculate_sha256(result.html), content=result.html)
        snapshot.html = html

        whois = (
            models.Whois(id=calculate_sha256(whois_content), content=whois_content)
            if whois_content
            else None
        )
        certificate = (
            models.Certificate(
                id=calculate_sha256(certificate_content), content=certificate_content
            )
            if certificate_content
            else None
        )

        # get script files
        script_files = cast(
            List[dataclasses.ScriptFile],
            await ScriptTask.process(snapshot, insert_to_db=False),
        )

        return dataclasses.SnapshotResult(
            screenshot=None,
            har=None,
            snapshot=snapshot,
            script_files=script_files,
            html=html,
            whois=whois,
            certificate=certificate,
        )
