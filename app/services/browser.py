import json
import tempfile
from typing import List, Optional, cast

from playwright import async_playwright
from playwright.async_api import Browser as PlaywrightBrowser
from playwright.async_api import CDPSession, Error, Playwright, Response

from app import dataclasses, models
from app.core import settings
from app.factories.har import HarFactory
from app.services.certificate import Certificate
from app.services.har import HarBuilder, HarReader
from app.services.whois import Whois
from app.utils.hash import calculate_sha256
from app.utils.network import (
    get_asn_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)


def find_ip_address(url: str, events: List[dataclasses.ResponseReceivedEvent]):
    for event in events:
        if event.response.url == url:
            return event.response.remote_ip_address

    hostname = cast(str, get_hostname_from_url(url))
    ip_address = cast(str, get_ip_address_by_hostname(hostname))
    return ip_address


async def launch_browser(p: Playwright) -> PlaywrightBrowser:
    return await p.chromium.launch(headless=True, chromiumSandbox=False)


async def run_browser(
    url: str,
    har_file_path: str,
    accept_language: Optional[str] = None,
    ignore_https_errors: bool = False,
    referer: Optional[str] = None,
    timeout: Optional[int] = None,
    user_agent: Optional[str] = None,
) -> dataclasses.BrowsingResult:
    async with async_playwright() as p:
        browser: PlaywrightBrowser = await launch_browser(p)
        context = await browser.newContext(
            recordHar={"path": har_file_path},
            ignoreHTTPSErrors=ignore_https_errors,
            userAgent=user_agent,
        )
        page = await context.newPage()

        client: CDPSession = await page.context.newCDPSession(page)
        await client.send("Network.enable")
        events: List[dataclasses.ResponseReceivedEvent] = []
        client.on(
            "Network.responseReceived",
            lambda data: events.append(
                dataclasses.ResponseReceivedEvent.from_dict(data)
            ),
        )

        headers = {}
        if accept_language is not None:
            headers["Accept-Language"] = accept_language
        await page.setExtraHTTPHeaders(headers)

        # default timeout = 30 seconds
        timeout = timeout or 30 * 1000
        res: Optional[Response] = await page.goto(
            url,
            referer=referer,
            timeout=timeout,
            waitUntil=settings.BROWSER_WAIT_UNTIL,
        )
        # detech the CDP session
        await client.detach()

        if res is None:
            raise Error("Cannot get the response")

        url = page.url
        screenshot = await page.screenshot()
        content = await page.content()
        user_agent = (await page.evaluate("() => navigator.userAgent"),)

        await context.close()
        await browser.close()

        return dataclasses.BrowsingResult(
            url=url,
            screenshot=screenshot,
            html=content,
            headers=res.headers,
            status=res.status,
            response_received_events=events,
            options={
                "accept_language": accept_language,
                "browser": browser.version,
                "ignore_https_errors": ignore_https_errors,
                "referer": referer,
                "timeout": timeout,
                "user_agent": user_agent,
            },
        )


async def preview(hostname: str, protocol="http") -> bytes:
    async with async_playwright() as p:
        browser = await launch_browser(p)
        page = await browser.newPage()

        await page.goto(
            f"{protocol}://{hostname}", waitUntil=settings.BROWSER_WAIT_UNTIL,
        )
        screenshot = await page.screenshot()
        await browser.close()

        return screenshot


def build_snapshot_result(
    submitted_url: str,
    browsing_result: dataclasses.BrowsingResult,
    har: Optional[dataclasses.HAR] = None,
) -> dataclasses.SnapshotResult:
    headers = browsing_result.headers
    server = headers.get("server")
    content_type = headers.get("content-type")
    content_length = headers.get("content-length")

    url = browsing_result.url
    ip_address = find_ip_address(url, browsing_result.response_received_events)
    hostname = cast(str, get_hostname_from_url(url))
    asn = get_asn_by_ip_address(ip_address) or ""

    script_files: List[dataclasses.ScriptFile] = []

    if har:
        har_reader = HarReader(har)
        script_files = har_reader.find_script_files()

    certificate_content = Certificate.load_and_dump_from_url(url)
    whois_content = Whois.whois(hostname)

    snapshot = models.Snapshot(
        url=url,
        submitted_url=submitted_url,
        status=browsing_result.status,
        headers=headers,
        hostname=hostname,
        ip_address=ip_address,
        asn=asn,
        server=server,
        content_length=content_length,
        content_type=content_type,
        options=browsing_result.options,
    )
    html = models.HTML(
        id=calculate_sha256(browsing_result.html), content=browsing_result.html
    )
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
    har = HarFactory.from_dataclass(har) if har else None

    return dataclasses.SnapshotResult(
        screenshot=browsing_result.screenshot,
        html=html,
        certificate=certificate,
        whois=whois,
        snapshot=snapshot,
        script_files=script_files,
        har=har,
    )


class Browser:
    @staticmethod
    async def take_snapshot(
        url: str,
        enable_har: bool = False,
        accept_language: Optional[str] = None,
        ignore_https_errors: bool = False,
        referer: Optional[str] = None,
        timeout: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> dataclasses.SnapshotResult:
        """Take a snapshot of a website by puppeteer

        Arguments:
            url {str} -- A URL of a website

        Keyword Arguments:
            accept_language {Optional[str]} -- Accept-language header to use (default: {None})
            ignore_https_errors {bool} -- Whether to ignore HTTPS errors (default: {False})
            referer {Optional[str]} -- Referer header to use (default: {None})
            timeout {Optional[int]} -- Maximum time to wait for in seconds (default: {None})
            user_agent {Optional[str]} -- User-agent header to use (default: {None})
            enable_har{Optional[str]} -- Whether to enable HAR recording (default: {False})

        Returns:
            SnapshotResult
        """
        submitted_url: str = url
        har_data: Optional[dict] = None
        try:
            with tempfile.NamedTemporaryFile() as fp:
                browsing_result = await run_browser(
                    url,
                    har_file_path=fp.name,
                    accept_language=accept_language,
                    referer=referer,
                    timeout=timeout,
                    ignore_https_errors=ignore_https_errors,
                    user_agent=user_agent,
                )
                har_data = json.loads(fp.read().decode())
        except Error as e:
            raise (e)

        har = HarBuilder.from_dict(
            har_data, events=browsing_result.response_received_events
        )

        snapshot_result = build_snapshot_result(submitted_url, browsing_result, har)
        snapshot_result.har = HarFactory.from_dataclass(har) if enable_har else None

        return snapshot_result

    @staticmethod
    async def preview(hostname: str) -> bytes:
        try:
            return await preview(hostname, "http")
        except Error:
            pass

        try:
            return await preview(hostname, "https")
        except Error:
            return b""
