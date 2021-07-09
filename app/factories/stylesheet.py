from functools import partial
from typing import List

import aiometer
import httpx
from d8s_hashes import sha256

from app import dataclasses, models
from app.services.har import is_stylesheet_content_type
from app.utils.http import get_http_resource, get_stylesheet_urls

MAX_AT_ONCE = 10


class StylesheetFactory:
    @staticmethod
    async def from_snapshot(
        snapshot: models.Snapshot,
    ) -> List[dataclasses.StylesheetFile]:
        urls = get_stylesheet_urls(
            url=snapshot.url,
            html=snapshot.html.content,
        )
        stylesheet_files: List[dataclasses.StylesheetFile] = []

        # Use the same settings as the original request
        headers = snapshot.request_headers

        verify = not snapshot.ignore_https_errors

        async with httpx.AsyncClient(verify=verify) as client:
            # Get sources
            tasks = [partial(get_http_resource, client, url, headers) for url in urls]
            if len(tasks) <= 0:
                return []

            results = await aiometer.run_all(tasks, max_at_once=MAX_AT_ONCE)
            for result in results:
                if result is None:
                    continue

                if result.content_type is None:
                    continue

                if not is_stylesheet_content_type(result.content_type):
                    continue

                file_id = sha256(result.content)
                file = models.File(id=file_id, content=result.content)
                stylesheet = models.Stylesheet(
                    url=result.url,
                    file_id=file_id,
                    # insert a dummy ID if a snapshot doesn't have ID
                    snapshot_id=snapshot.id or -1,
                )
                stylesheet_files.append(
                    dataclasses.StylesheetFile(stylesheet=stylesheet, file=file)
                )

        return stylesheet_files
