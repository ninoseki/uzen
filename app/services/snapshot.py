from typing import Optional

import httpx
from loguru import logger
from playwright import Error
from tortoise.exceptions import IntegrityError
from tortoise.transactions import in_transaction

from app.core import settings
from app.core.exceptions import TakeSnapshotError
from app.models.scripts import Script
from app.models.snapshots import Snapshot
from app.schemas.utils import SnapshotResult
from app.services.browser import Browser
from app.services.fake_browser import FakeBrowser


def use_playwright(host: Optional[str] = None) -> bool:
    return host is None


def use_httpx(host: Optional[str] = None) -> bool:
    if host is not None:
        return True
    return settings.HTTPX_FALLBACK


async def take_snapshot(
    url: str,
    accept_language: Optional[str] = None,
    host: Optional[str] = None,
    ignore_https_errors: Optional[bool] = None,
    referer: Optional[str] = None,
    timeout: Optional[int] = None,
    user_agent: Optional[str] = None,
) -> SnapshotResult:

    timeout = timeout or 30000
    ignore_https_errors = ignore_https_errors or False

    result = None
    errors = []

    # Skip playwright if a host is not None
    # because Chromium prohibits setting "host" header.
    # ref. https://github.com/puppeteer/puppeteer/issues/4575#issuecomment-511259872
    if use_playwright(host):
        try:
            result = await Browser.take_snapshot(
                url,
                accept_language=accept_language,
                ignore_https_errors=ignore_https_errors,
                referer=referer,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Error as e:
            message = f"Failed to take a snapshot by playwright: {e}."
            logger.debug(message)
            errors.append(message)

    if result is not None:
        return result

    # raise an error if HTTPX is not enabled
    if not use_httpx(host):
        raise TakeSnapshotError("\n".join(errors))

    # fallback to HTTPX
    logger.debug("Fallback to HTTPX")
    try:
        result = await FakeBrowser.take_snapshot(
            url,
            accept_language=accept_language,
            host=host,
            ignore_https_errors=ignore_https_errors,
            referer=referer,
            timeout=timeout,
            user_agent=user_agent,
        )
    except httpx.HTTPError as e:
        message = f"Failed to take a snapshot by HTTPX: {e}."
        logger.debug(message)
        errors.append(message)

    if result is not None:
        return result

    raise TakeSnapshotError("\n".join(errors))


async def save_snapshot(result: SnapshotResult) -> Snapshot:
    async with in_transaction():
        snapshot = result.snapshot
        await snapshot.save()

        files = [script_file.file for script_file in result.script_files]
        for file in files:
            try:
                await file.save()
            except IntegrityError:
                # ignore the intergrity error
                # e.g. tortoise.exceptions.IntegrityError: UNIQUE constraint failed: files.id
                pass

        scripts = [script_file.script for script_file in result.script_files]
        for script in scripts:
            script.snapshot_id = snapshot.id
        await Script.bulk_create(scripts)

        return snapshot
