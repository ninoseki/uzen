from pyppeteer import launch
from pyppeteer.errors import PyppeteerError
from typing import Optional
import asyncio
import hashlib

from uzen.models import Snapshot
from uzen.utils import (
    get_asn_by_ip_address,
    get_certificate_from_url,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)
from uzen.whois import Whois


class Browser:
    @staticmethod
    async def take_snapshot(url: str, user_agent: Optional[str] = None, timeout: Optional[int] = None) -> Snapshot:
        try:
            browser = await launch(headless=True)
            page = await browser.newPage()

            if user_agent is not None:
                await page.setUserAgent(user_agent)

            # default timeout = 30 seconds
            timeout = timeout if timeout is None else 30 * 1000
            res = await page.goto(url, timeout=timeout)

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
        certificate = get_certificate_from_url(url)
        ip_address = get_ip_address_by_hostname(hostname)
        asn = get_asn_by_ip_address(ip_address)
        whois = Whois.whois(hostname)

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
            whois=whois,
            certificate=certificate,
            screenshot=screenshot,
        )
        return snapshot
