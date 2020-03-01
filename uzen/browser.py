from pyppeteer import launch
from pyppeteer.errors import PyppeteerError
import asyncio
import hashlib

from uzen.models import Snapshot
from uzen.utils import get_hostname_from_url
from uzen.utils import get_ip_address_by_hostname, get_asn_by_ip_address


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
            sha256 = hashlib.sha256(body.encode('utf-8')).hexdigest()
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
        asn = get_asn_by_ip_address(ip_address)

        snapshot = await Snapshot(
            url=url,
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
            screenshot=screenshot,
        )
        return snapshot
