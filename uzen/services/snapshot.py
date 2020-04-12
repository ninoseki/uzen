from typing import Optional

import httpx
from loguru import logger
from pyppeteer.errors import PyppeteerError
from tortoise.transactions import in_transaction

from uzen.core.exceptions import TakeSnapshotError
from uzen.models.snapshots import Snapshot
from uzen.schemas.utils import SnapshotResult
from uzen.services.browser import Browser
from uzen.services.fake_browser import FakeBrowser


async def take_snapshot(
    url: str,
    accept_language: Optional[str],
    ignore_https_errors: Optional[bool],
    referer: Optional[str],
    timeout: Optional[int],
    user_agent: Optional[str],
) -> SnapshotResult:

    timeout = timeout or 30000
    ignore_https_errors = ignore_https_errors or False

    result = None
    errors = []
    try:
        result = await Browser.take_snapshot(
            url,
            accept_language=accept_language,
            ignore_https_errors=ignore_https_errors,
            referer=referer,
            timeout=timeout,
            user_agent=user_agent,
        )
    except (PyppeteerError, UnboundLocalError) as e:
        message = f"Failed to take a snapshot by pyppeteer: {e}."
        logger.debug(message)
        errors.append(message)

    if result is not None:
        return result

    # fallback to fake browser (httpx)
    if result is None:
        logger.debug("Fallback to httpx")
        try:
            result = await FakeBrowser.take_snapshot(
                url,
                accept_language=accept_language,
                ignore_https_errors=ignore_https_errors,
                referer=referer,
                timeout=timeout,
                user_agent=user_agent,
            )
        except httpx.HTTPError as e:
            message = f"Failed to take a snapshot by httpx: {e}."
            logger.debug(message)
            errors.append(message)

    if result is not None:
        return result

    raise TakeSnapshotError("\n".join(errors))


async def save_snapshot(result: SnapshotResult) -> Snapshot:
    async with in_transaction():
        snapshot = result.snapshot
        screenshot = result.screenshot

        await snapshot.save()
        screenshot.snapshot_id = snapshot.id
        await screenshot.save()

        snapshot.screenshot = screenshot
        return snapshot
