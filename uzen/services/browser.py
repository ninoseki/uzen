import asyncio
import base64
from typing import List, Optional, cast

import playwright
from playwright import Error, async_playwright
from playwright.network import Response
from playwright.page import Page
from playwright.playwright import Playwright

from uzen.core import settings
from uzen.models.screenshots import Screenshot
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot
from uzen.schemas.utils import SnapshotResult
from uzen.services.certificate import Certificate
from uzen.services.utils import (
    calculate_sha256,
    get_asn_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)
from uzen.services.whois import Whois


async def launch_browser(p: Playwright) -> playwright.browser.Browser:
    if settings.BROWSER_WS_ENDPOINT != "":
        return await p.chromium.connect(wsEndpoint=settings.BROWSER_WS_ENDPOINT)

    return await p.chromium.launch(headless=True, chromiumSandbox=False)


def is_js_content_type(content_type: str) -> bool:
    return content_type.startswith("application/javascript") or content_type.startswith(
        "text/javascript"
    )


class Browser:
    @staticmethod
    async def take_snapshot(
        url: str,
        accept_language: Optional[str] = None,
        ignore_https_errors: bool = False,
        referer: Optional[str] = None,
        timeout: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> SnapshotResult:
        """Take a snapshot of a website by puppeteer

        Arguments:
            url {str} -- A URL of a website

        Keyword Arguments:
            accept_language {Optional[str]} -- Accept-language header to use (default: {None})
            ignore_https_errors {bool} -- Whether to ignore HTTPS errors (default: {False})
            referer {Optional[str]} -- Referer header to use (default: {None})
            timeout {Optional[int]} -- Maximum time to wait for in seconds (default: {None})
            user_agent {Optional[str]} -- User-agent header to use (default: {None})

        Returns:
            SnapshotResult
        """
        submitted_url: str = url
        try:
            async with async_playwright() as p:
                browser: playwright.browser.Browser = await launch_browser(p)
                page: Page = await browser.newPage(
                    ignoreHTTPSErrors=ignore_https_errors, userAgent=user_agent
                )

                headers = {}
                if accept_language is not None:
                    headers["Accept-Language"] = accept_language
                await page.setExtraHTTPHeaders(headers)

                # intercept responses on page to get scripts
                scripts: List[Script] = []

                async def handle_response(response: Response) -> None:
                    content_type: str = response.headers.get("content-type", "")
                    if response.ok and is_js_content_type(content_type):
                        content = await response.text()
                        scripts.append(
                            Script(
                                url=response.url,
                                content=content,
                                sha256=calculate_sha256(content),
                            )
                        )

                page.on(
                    "response",
                    lambda response: asyncio.create_task(handle_response(response)),
                )

                # default timeout = 30 seconds
                timeout = timeout or 30 * 1000
                res: Response = await page.goto(
                    url,
                    referer=referer,
                    timeout=timeout,
                    waitUntil=settings.BROWSER_WAIT_UNTIL,
                )

                request = {
                    "accept_language": accept_language,
                    "browser": browser.version,
                    "ignore_https_errors": ignore_https_errors,
                    "referer": referer,
                    "timeout": timeout,
                    "user_agent": await page.evaluate("() => navigator.userAgent"),
                }

                url = page.url
                status = res.status
                screenshot_data = await page.screenshot()
                body = await page.content()
                sha256 = calculate_sha256(body)
                headers = res.headers

                await browser.close()
        except Error as e:
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
        screenshot = Screenshot()
        screenshot.data = base64.b64encode(screenshot_data).decode()

        return SnapshotResult(
            screenshot=screenshot, snapshot=snapshot, scripts=scripts,
        )

    @staticmethod
    async def preview(hostname: str) -> Screenshot:
        async def _preview(hostname: str, protocol="http") -> Screenshot:
            try:
                async with async_playwright() as p:
                    browser = await launch_browser(p)
                    page = await browser.newPage()
                    # try with http
                    await page.goto(
                        f"{protocol}://{hostname}",
                        waitUntil=settings.BROWSER_WAIT_UNTIL,
                    )
                    screenshot_data = await page.screenshot()
                    await browser.close()

                    screenshot = Screenshot()
                    screenshot.data = base64.b64encode(screenshot_data).decode()
                    return screenshot
            except Error as e:
                raise (e)

        try:
            return await _preview(hostname, "http")
        except Error:
            pass

        try:
            return await _preview(hostname, "https")
        except Error:
            screenshot = Screenshot()
            screenshot.data = ""
            return screenshot
