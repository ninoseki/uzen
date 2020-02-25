from pyppeteer import launch
from pyppeteer.errors import PyppeteerError
import asyncio

from uzen.models import Snapshot
from uzen.utils import get_hostname_from_url
from uzen.utils import get_ip_address_by_hostname


class Browser:
    @staticmethod
    async def take_snapshot(url: str) -> Snapshot:
        try:
            browser = await launch(headless=True)
            page = await browser.newPage()
            res = await page.goto(url)

            status = res.status
            screenshot = await page.screenshot(encoding="base64")
            body = await res.text()
            headers = res.headers
        except PyppeteerError as e:
            await browser.close()
            raise (e)
        finally:
            if browser is not None:
                await browser.close()

        server = headers.get("server")
        content_type = headers.get("content-type")
        content_length = headers.get("content-length")

        hostname = get_hostname_from_url(url)
        ip_address = get_ip_address_by_hostname(hostname)

        snapshot = await Snapshot(
            url=url,
            status=status,
            body=body,
            headers=headers,
            hostname=hostname,
            ip_address=ip_address,
            server=server,
            content_length=content_length,
            content_type=content_type,
            screenshot=screenshot,
        )
        return snapshot
