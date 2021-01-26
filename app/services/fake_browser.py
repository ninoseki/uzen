from typing import List, Optional, cast

import httpx

from app import dataclasses
from app.dataclasses.browser import BrowsingResult
from app.services.browser import build_snapshot_result
from app.tasks.script import ScriptTask

DEFAULT_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
DEFAULT_AL = "en-US"
DEFAULT_REFERER = ""


async def run_httpx(
    url: str,
    host: Optional[str] = None,
    accept_language: Optional[str] = None,
    ignore_https_errors: bool = False,
    referer: Optional[str] = None,
    timeout: Optional[int] = None,
    user_agent: Optional[str] = None,
) -> BrowsingResult:
    verify = not ignore_https_errors

    # default timeout = 30 seconds
    timeout = int(timeout / 1000) if timeout is not None else 30

    user_agent = user_agent or DEFAULT_UA

    headers = {
        "user-agent": user_agent,
        "accept-language": accept_language or DEFAULT_AL,
        "referer": referer or DEFAULT_REFERER,
    }
    if host is not None:
        headers["host"] = host

    async with httpx.AsyncClient(verify=verify) as client:
        res = await client.get(
            url, headers=headers, timeout=timeout, allow_redirects=True,
        )
        headers = {k.lower(): v for (k, v) in res.headers.items()}
        return BrowsingResult(
            url=str(res.url),
            status=res.status_code,
            screenshot=None,
            html=res.text,
            headers=headers,
            options={
                "accept_language": accept_language,
                "browser": "httpx",
                "host": host,
                "ignore_https_errors": ignore_https_errors,
                "referer": referer,
                "timeout": timeout,
                "user_agent": user_agent,
            },
        )


class FakeBrowser:
    @staticmethod
    async def take_snapshot(
        url: str,
        accept_language: Optional[str] = None,
        host: Optional[str] = None,
        ignore_https_errors: bool = False,
        referer: Optional[str] = None,
        timeout: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> dataclasses.SnapshotResult:
        """Take a snapshot of a website by httpx

        Arguments:
            url {str} -- A URL of a website

        Keyword Arguments:
            accept_language {Optional[str]} -- Accept-language header to use (default: {None})
            host {Optional[str]} -- Host header to use (default: {None})
            ignore_https_errors {bool} -- Whether to ignore HTTPS errors (default: {False})
            referer {Optional[str]} -- Referer header to use (default: {None})
            timeout {Optional[int]} -- Maximum time to wait for in seconds (default: {None})
            user_agent {Optional[str]} -- User-agent header to use (default: {None})

        Returns:
            SnapshotResult
        """
        submitted_url: str = url

        try:
            browsing_result = await run_httpx(
                url,
                host=host,
                accept_language=accept_language,
                referer=referer,
                timeout=timeout,
                ignore_https_errors=ignore_https_errors,
                user_agent=user_agent,
            )
        except httpx.HTTPError as e:
            raise (e)

        snapshot_result = build_snapshot_result(submitted_url, browsing_result)

        # set html to extract scripts
        snapshot = snapshot_result.snapshot
        snapshot.html = snapshot_result.html

        # get script files
        script_files = cast(
            List[dataclasses.ScriptFile],
            await ScriptTask.process(snapshot, insert_to_db=False),
        )
        snapshot_result.script_files = script_files

        return snapshot_result
