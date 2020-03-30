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
    user_agent: Optional[str],
    accept_language: Optional[str],
    timeout: Optional[int],
    ignore_https_errors: Optional[bool],
) -> Snapshot:

    timeout = timeout or 30000
    ignore_https_errors = ignore_https_errors or False

    snapshot = None
    errors = []
    try:
        snapshot = await Browser.take_snapshot(
            url,
            user_agent=user_agent,
            accept_language=accept_language,
            timeout=timeout,
            ignore_https_errors=ignore_https_errors,
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
                user_agent=user_agent,
                accept_language=accept_language,
                timeout=timeout,
                ignore_https_errors=ignore_https_errors,
            )
        except httpx.HTTPError as e:
            message = f"Failed to take a snapshot by httpx: {e}."
            logger.debug(message)
            errors.append(message)

    if snapshot is not None:
        return snapshot

    raise TakeSnapshotError("\n".join(errors))
