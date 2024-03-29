from typing import Dict, Optional

from cached_property import cached_property
from loguru import logger
from playwright.async_api import Error, async_playwright

from app import dataclasses
from app.core.exceptions import TakeSnapshotError
from app.services.browsers.playwright import (
    PlaywrightBrowser,
    launch_playwright_browser,
)
from app.types import WaitUntilType

# default timeout = 30s
DEFAULT_TIMEOUT = 30000


async def take_screenshot(hostname: str, protocol: str = "http") -> bytes:
    async with async_playwright() as playwright:
        browser = await launch_playwright_browser(playwright)
        page = await browser.new_page()

        await page.goto(
            f"{protocol}://{hostname}",
        )
        screenshot = await page.screenshot()
        await browser.close()

        return screenshot


class Browser:
    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        enable_har: bool = False,
        ignore_https_errors: bool = False,
        device_name: Optional[str] = None,
        timeout: Optional[int] = None,
        wait_until: WaitUntilType = "load",
    ):
        self.headers: Dict[str, str] = headers or {}
        self.enable_har: bool = enable_har
        self.ignore_https_errors: bool = ignore_https_errors
        self.timeout: int = timeout if timeout is not None else DEFAULT_TIMEOUT
        self.device_name: Optional[str] = device_name
        self.wait_until: WaitUntilType = wait_until

    @cached_property
    def options(self) -> dataclasses.BrowserOptions:
        return dataclasses.BrowserOptions(
            enable_har=self.enable_har,
            ignore_https_errors=self.ignore_https_errors,
            timeout=self.timeout,
            device_name=self.device_name,
            headers=self.headers,
            wait_until=self.wait_until,
        )

    async def take_snapshot(self, url: str) -> dataclasses.SnapshotModelWrapper:
        result: Optional[dataclasses.SnapshotModelWrapper] = None
        error: Optional[Exception] = None

        try:
            result = await PlaywrightBrowser.take_snapshot(url, self.options)
        except Error as e:
            message = "Failed to take a snapshot by playwright"
            logger.debug(message)
            logger.exception(e)
            error = e

        if result is not None:
            return result

        raise TakeSnapshotError(error)

    @staticmethod
    async def preview(hostname: str) -> bytes:
        try:
            return await take_screenshot(hostname, "http")
        except Error:
            pass

        try:
            return await take_screenshot(hostname, "https")
        except Error:
            return b""
