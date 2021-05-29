from typing import Any, Dict, Optional

from playwright.async_api import Browser, Error, Playwright, Response, async_playwright
from playwright_har_tracer import HarTracer

from app import dataclasses
from app.services.browsers import AbstractBrowser, build_snapshot_result


async def launch_playwright_browser(playwright: Playwright) -> Browser:
    return await playwright.chromium.launch(headless=True, chromium_sandbox=False)


async def run_playwright_browser(
    url: str, options: dataclasses.BrowsingOptions
) -> dataclasses.BrowsingResult:
    async with async_playwright() as playwright:
        browser: Browser = await launch_playwright_browser(playwright)

        device: Dict[str, Any] = (
            playwright.devices.get(options.device_name, {})
            if options.device_name is not None
            else {}
        )
        # do not use the user agent if the device is given
        user_agent = options.headers.get("user-agent", None)
        if not device:
            device["user_agent"] = user_agent

        context = await browser.new_context(
            **device,
            ignore_https_errors=options.ignore_https_errors,
        )

        tracer = HarTracer(context=context, browser_name=playwright.chromium.name)
        page = await context.new_page()
        client = await context.new_cdp_session(page)
        await tracer.enable_response_received_event_tracing(client)

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
        if res is None:
            raise Error("Cannot get the response")

        url = page.url
        screenshot = await page.screenshot()
        content = await page.content()

        har = await tracer.flush()

        # detach the CDP session
        await client.detach()

        await context.close()
        await browser.close()

        return dataclasses.BrowsingResult(
            url=url,
            screenshot=screenshot,
            html=content,
            response_headers=res.headers,
            request_headers=res.request.headers,
            status=res.status,
            har=har,
            options=options,
        )


class PlaywrightBrowser(AbstractBrowser):
    @staticmethod
    async def take_snapshot(
        url: str,
        options: dataclasses.BrowsingOptions,
    ) -> dataclasses.SnapshotResult:
        submitted_url: str = url

        try:
            browsing_result = await run_playwright_browser(url, options=options)
        except Error as e:
            raise (e)

        snapshot_result = await build_snapshot_result(submitted_url, browsing_result)

        return snapshot_result
