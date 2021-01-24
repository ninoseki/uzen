from typing import Optional

import httpx
from loguru import logger
from playwright import Error
from tortoise.exceptions import IntegrityError
from tortoise.models import Model
from tortoise.transactions import in_transaction

from app import dataclasses, models
from app.core import settings
from app.core.exceptions import TakeSnapshotError
from app.services.browser import Browser
from app.services.fake_browser import FakeBrowser
from app.utils.script import save_script_files


def use_playwright(host: Optional[str] = None) -> bool:
    return host is None


def use_httpx(host: Optional[str] = None) -> bool:
    if host is not None:
        return True
    return settings.HTTPX_FALLBACK


async def take_snapshot(
    url: str,
    enableHAR: bool = False,
    accept_language: Optional[str] = None,
    host: Optional[str] = None,
    ignore_https_errors: Optional[bool] = None,
    referer: Optional[str] = None,
    timeout: Optional[int] = None,
    user_agent: Optional[str] = None,
) -> dataclasses.SnapshotResult:

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
                enableHAR=enableHAR,
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


async def save_ignore_integrity_error(model: Model):
    try:
        await model.save()
    except IntegrityError:
        # ignore the intergrity error
        # e.g. tortoise.exceptions.IntegrityError: UNIQUE constraint failed: files.id
        pass


async def save_snapshot(result: dataclasses.SnapshotResult) -> models.Snapshot:
    async with in_transaction():
        snapshot = result.snapshot

        # save html, certificate, whois before saving snapshot
        html = result.html
        await save_ignore_integrity_error(html)
        snapshot.html_id = html.id

        certificate = result.certificate
        if certificate:
            await save_ignore_integrity_error(certificate)
            snapshot.certificate_id = certificate.id

        whois = result.whois
        if whois:
            await save_ignore_integrity_error(whois)
            snapshot.whois_id = whois.id

        # save snapshot
        await snapshot.save()

        # save scripts
        await save_script_files(result.script_files, snapshot.id)

        # save har
        har = result.har
        if har:
            har.snapshot_id = snapshot.id
            await har.save()

        return snapshot
