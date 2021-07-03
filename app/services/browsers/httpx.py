import httpx

from app import dataclasses
from app.arq.tasks.script import ScriptTask
from app.arq.tasks.stylesheet import StylesheetTask
from app.services.browsers import AbstractBrowser, build_snapshot_result

DEFAULT_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
DEFAULT_AL = "en-US"


async def run_httpx(
    url: str, options: dataclasses.BrowsingOptions
) -> dataclasses.BrowsingResult:
    verify = not options.ignore_https_errors

    async with httpx.AsyncClient(verify=verify) as client:
        res = await client.get(
            url,
            headers=options.headers,
            timeout=options.timeout,
            allow_redirects=True,
        )

        return dataclasses.BrowsingResult(
            url=str(res.url),
            status=res.status_code,
            screenshot=None,
            html=res.text,
            request_headers=options.headers,
            response_headers=dict(res.headers),
            options=options,
        )


class HttpxBrowser(AbstractBrowser):
    @staticmethod
    async def take_snapshot(
        url: str,
        options: dataclasses.BrowsingOptions,
    ) -> dataclasses.SnapshotResult:
        submitted_url: str = url

        try:
            browsing_result = await run_httpx(url, options)
        except httpx.HTTPError as e:
            raise (e)

        snapshot_result = await build_snapshot_result(submitted_url, browsing_result)

        # set html to extract scripts
        snapshot = snapshot_result.snapshot
        snapshot.html = snapshot_result.html

        # get script files
        script_files = await ScriptTask.process(snapshot)
        snapshot_result.script_files = script_files

        # get stylesheet files
        stylesheet_files = await StylesheetTask.process(snapshot)

        snapshot_result.stylesheet_files = stylesheet_files

        return snapshot_result
