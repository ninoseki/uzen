import asyncio
from typing import List, Optional, cast

from playwright import async_playwright
from playwright.async_api import Browser as PlaywrightBrowser
from playwright.async_api import Error, Page, Playwright, Response

from app import dataclasses, models, schemas
from app.core import settings
from app.services.certificate import Certificate
from app.services.whois import Whois
from app.utils.hash import calculate_sha256
from app.utils.network import (
    get_asn_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)


async def launch_browser(p: Playwright) -> PlaywrightBrowser:
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

        Returns:
            SnapshotResult
        """
        submitted_url: str = url
        try:
            async with async_playwright() as p:
                browser: PlaywrightBrowser = await launch_browser(p)
                page: Page = await browser.newPage(
                    ignoreHTTPSErrors=ignore_https_errors, userAgent=user_agent
                )

                headers = {}
                if accept_language is not None:
                    headers["Accept-Language"] = accept_language
                await page.setExtraHTTPHeaders(headers)

                # intercept responses on page to get scripts
                script_files: List[schemas.ScriptFile] = []

                async def handle_response(response: Response) -> None:
                    content_type: str = response.headers.get("content-type", "")
                    if response.ok and is_js_content_type(content_type):
                        content = await response.text()
                        sha256 = calculate_sha256(content)

                        script = models.Script(url=response.url, file_id=sha256)
                        file = models.File(id=sha256, content=content)
                        script_files.append(
                            dataclasses.ScriptFile(script=script, file=file)
                        )

                page.on(
                    "response",
                    lambda response: asyncio.create_task(handle_response(response)),
                )

                # default timeout = 30 seconds
                timeout = timeout or 30 * 1000
                res: Optional[Response] = await page.goto(
                    url,
                    referer=referer,
                    timeout=timeout,
                    waitUntil=settings.BROWSER_WAIT_UNTIL,
                )

                if res is None:
                    raise Error("Cannot get the response")

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
                screenshot = await page.screenshot()
                html_content = await page.content()
                headers = res.headers

                await browser.close()
        except Error as e:
            raise (e)

        server = headers.get("server")
        content_type = headers.get("content-type")
        content_length = headers.get("content-length")

        hostname = cast(str, get_hostname_from_url(url))
        ip_address = cast(str, get_ip_address_by_hostname(hostname))
        asn = get_asn_by_ip_address(ip_address) or ""

        certificate_content = Certificate.load_and_dump_from_url(url)
        whois_content = Whois.whois(hostname)

        snapshot = models.Snapshot(
            url=url,
            submitted_url=submitted_url,
            status=status,
            headers=headers,
            hostname=hostname,
            ip_address=ip_address,
            asn=asn,
            server=server,
            content_length=content_length,
            content_type=content_type,
            request=request,
        )
        html = models.HTML(id=calculate_sha256(html_content), content=html_content)
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

        return dataclasses.SnapshotResult(
            screenshot=screenshot,
            html=html,
            certificate=certificate,
            whois=whois,
            snapshot=snapshot,
            script_files=script_files,
        )

    @staticmethod
    async def preview(hostname: str) -> bytes:
        async def _preview(hostname: str, protocol="http") -> bytes:
            try:
                async with async_playwright() as p:
                    browser = await launch_browser(p)
                    page = await browser.newPage()
                    # try with http
                    await page.goto(
                        f"{protocol}://{hostname}",
                        waitUntil=settings.BROWSER_WAIT_UNTIL,
                    )
                    screenshot = await page.screenshot()
                    await browser.close()

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
            return b""
