from typing import Optional

import httpx
from loguru import logger
from pyppeteer.errors import PyppeteerError

from uzen.core.exceptions import TakeSnapshotError
from uzen.models.snapshots import Snapshot
from uzen.services.browser import Browser
from uzen.services.fake_browser import FakeBrowser


async def take_snapshot(
    url: str,
    accept_language: Optional[str],
    ignore_https_errors: Optional[bool],
    referer: Optional[str],
    timeout: Optional[int],
    user_agent: Optional[str],
) -> Snapshot:

    timeout = timeout or 30000
    ignore_https_errors = ignore_https_errors or False

    snapshot = None
    errors = []
    try:
        snapshot = await Browser.take_snapshot(
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

    if snapshot is not None:
        return snapshot

    # fallback to fake browser (httpx)
    if snapshot is None:
        logger.debug("Fallback to httpx")
        try:
            snapshot = await FakeBrowser.take_snapshot(
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

    if snapshot is not None:
        return snapshot

    raise TakeSnapshotError("\n".join(errors))
