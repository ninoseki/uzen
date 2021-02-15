import json
import tempfile
from typing import List, Optional

from playwright.async_api import (
    Browser,
    CDPSession,
    Error,
    Playwright,
    Response,
    async_playwright,
)

from app import dataclasses
from app.factories.har import HarFactory
from app.services.browsers import AbstractBrowser, build_snapshot_result
from app.services.har import HarBuilder


async def launch_playwright_browser(playwright: Playwright) -> Browser:
    return await playwright.chromium.launch(headless=True, chromium_sandbox=False)


async def run_playwright_browser(
    url: str, har_file_path: str, options: dataclasses.BrowsingOptions
) -> dataclasses.BrowsingResult:
    async with async_playwright() as playwright:
        browser: Browser = await launch_playwright_browser(playwright)

        device: dict = (
            playwright.devices.get(options.device_name, {})
            if options.device_name is not None
            else {}
        )
        # do not use the user agent if the device is given
        user_agent = options.headers.get("user-agent", None)
        if device is None:
            device["user_agent"] = user_agent

        context = await browser.new_context(
            **device,
            record_har_path=har_file_path,
            ignore_https_errors=options.ignore_https_errors,
        )
        page = await context.new_page()

        # record Network.responseReceived events to enrich HAR
        client: CDPSession = await page.context.new_cdp_session(page)
        await client.send("Network.enable")

        events: List[dataclasses.ResponseReceivedEvent] = []
        client.on(
            "Network.responseReceived",
            lambda data: events.append(
                dataclasses.ResponseReceivedEvent.from_dict(data)
            ),
        )

        # work on copy
        headers = options.headers.copy()

        # delete the user agent because it is already set as a context
        headers.pop("user-agent", None)
        # delete the referer because it is used in "goto"
        referer = headers.pop("referer", None)

        if headers:
            await page.set_extra_http_headers(headers)

        res: Optional[Response] = await page.goto(
            url, referer=referer, timeout=options.timeout, wait_until=options.wait_until
        )

        # detech the CDP session
        await client.detach()

        if res is None:
            raise Error("Cannot get the response")

        url = page.url
        screenshot = await page.screenshot()
        content = await page.content()

        await context.close()
        await browser.close()

        return dataclasses.BrowsingResult(
            url=url,
            screenshot=screenshot,
            html=content,
            response_headers=res.headers,
            request_headers=res.request.headers,
            status=res.status,
            response_received_events=events,
            options=options,
        )


class PlaywrightBrowser(AbstractBrowser):
    @staticmethod
    async def take_snapshot(
        url: str, options: dataclasses.BrowsingOptions,
    ) -> dataclasses.SnapshotResult:
        submitted_url: str = url
        har_data: Optional[dict] = None
        try:
            with tempfile.NamedTemporaryFile() as fp:
                browsing_result = await run_playwright_browser(
                    url, har_file_path=fp.name, options=options
                )
                har_data = json.loads(fp.read().decode())
        except Error as e:
            raise (e)

        har = HarBuilder.from_dict(
            har_data, events=browsing_result.response_received_events
        )

        snapshot_result = await build_snapshot_result(
            submitted_url, browsing_result, har
        )
        snapshot_result.har = (
            HarFactory.from_dataclass(har) if options.enable_har else None
        )

        return snapshot_result
