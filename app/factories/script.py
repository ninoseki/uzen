from functools import partial
from typing import List

import aiometer
import httpx

from app import dataclasses, models
from app.dataclasses.utils import ScriptFile
from app.utils.hash import calculate_sha256
from app.utils.http import get_http_resource, get_script_urls

MAX_AT_ONCE = 10


class ScriptFactory:
    @staticmethod
    async def from_snapshot(snapshot: models.Snapshot) -> List[dataclasses.ScriptFile]:
        urls = get_script_urls(
            url=snapshot.url,
            html=snapshot.html.content,
        )
        script_files: List[dataclasses.ScriptFile] = []

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

                sha256 = calculate_sha256(result.content)
                file = models.File(id=sha256, content=result.content)
                script = models.Script(
                    url=result.url,
                    file_id=sha256,
                    # insert a dummy ID if a snapshot doesn't have ID
                    snapshot_id=snapshot.id or -1,
                )
                script_files.append(ScriptFile(script=script, file=file))

        return script_files
