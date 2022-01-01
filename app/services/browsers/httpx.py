import httpx

from app import dataclasses
from app.arq.tasks.classes.script import ScriptTask
from app.arq.tasks.classes.stylesheet import StylesheetTask

from .abstract import AbstractBrowser
from .utils import build_snapshot_model_wrapper


async def run_httpx(
    url: str, options: dataclasses.BrowserOptions
) -> dataclasses.Snapshot:
    verify = not options.ignore_https_errors

    async with httpx.AsyncClient(
        verify=verify,
        headers=options.headers,
        timeout=options.timeout,
        follow_redirects=True,
    ) as client:
        res = await client.get(url)

        return dataclasses.Snapshot(
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
        options: dataclasses.BrowserOptions,
    ) -> dataclasses.SnapshotModelWrapper:
        submitted_url: str = url

        try:
            snapshot = await run_httpx(url, options)
        except httpx.HTTPError as e:
            raise (e)

        wrapper = await build_snapshot_model_wrapper(submitted_url, snapshot)

        # set html to extract scripts
        snapshot = wrapper.snapshot
        snapshot.html = wrapper.html

        # get script files
        script_files = await ScriptTask.process(snapshot)
        wrapper.script_files = script_files

        # get stylesheet files
        stylesheet_files = await StylesheetTask.process(snapshot)
        wrapper.stylesheet_files = stylesheet_files

        return wrapper
