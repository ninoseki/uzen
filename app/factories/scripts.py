import dataclasses
from functools import partial
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiometer
import httpx
from bs4 import BeautifulSoup

from app import models, schemas
from app.dataclasses.utils import ScriptFile
from app.utils.hash import calculate_sha256

MAX_AT_ONCE = 10


def extract_base_path(path: str) -> str:
    """Extract base path from a path (or remove a filename from the path)

    Arguments:
        path {str} -- A path e.g. /foo/bar/index.html

    Returns:
        str -- A base path (e.g. /foo/bar/)
    """
    parts = path.split("/")
    return "/".join(parts[:-1])


def normalize_source(url: str, source: str) -> str:
    """Convert a URL to an absolute URL

    Arguments:
        url {str} -- A URL
        source {str} -- Source of a script

    Returns:
        str -- An absolute URL
    """
    if source.startswith("http://") or source.startswith("https://"):
        return source

    parsed = urlparse(url)
    base_path = extract_base_path(parsed.path)
    base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}"

    if source.startswith("/"):
        return f"{base_url}{source}"

    return f"{base_url}/{source}"


def get_script_sources(url: str, body: str) -> List[str]:
    """Get script sources

    Arguments:
        url {str} -- A URL
        body {str} -- An HTTP response body

    Returns:
        List[str] -- A list of script sources
    """
    html = BeautifulSoup(body, "html.parser")

    sources: List[str] = []
    for script in html.find_all("script"):
        source = script.attrs.get("src")
        if source is not None:
            sources.append(normalize_source(url, source))

    return list(set(sources))


@dataclasses.dataclass
class ScriptContent:
    source: str
    content: str


async def get_script_content(
    client, source: str, headers: Dict
) -> Optional[ScriptContent]:
    """Get script contents

    Arguments:
        source {str} -- A source of a script (an absolute URL)

    Returns:
        Optional[ScriptContent] -- A fetched result
    """
    try:
        res = await client.get(source, headers=headers)
        res.raise_for_status()
        return ScriptContent(source=source, content=res.text)
    except httpx.HTTPError:
        return None


class ScriptFactory:
    @staticmethod
    async def from_snapshot(snapshot: models.Snapshot) -> List[ScriptFile]:
        sources = get_script_sources(url=snapshot.url, body=snapshot.html.content)
        script_files: List[schemas.ScriptFile] = []

        # Use the same settings as the original request
        headers = {
            "accept_language": snapshot.request.get("accept_language"),
            "host": snapshot.request.get("host"),
            "user_agent": snapshot.request.get("user_agent"),
        }
        # Remove none value
        headers = {k: v for k, v in headers.items() if v is not None}

        ignore_https_errors = snapshot.request.get("ignore_https_errors")
        verify = not ignore_https_errors

        async with httpx.AsyncClient(verify=verify) as client:
            # Get sources
            tasks = [
                partial(get_script_content, client, source, headers)
                for source in sources
            ]
            if len(tasks) <= 0:
                return []

            results = await aiometer.run_all(tasks, max_at_once=MAX_AT_ONCE)
            for result in results:
                if result is None:
                    continue

                sha256 = calculate_sha256(result.content)
                file = models.File(id=sha256, content=result.content)
                script = models.Script(
                    url=result.source,
                    file_id=sha256,
                    # insert a dummy ID if a snapshot doesn't have ID
                    snapshot_id=snapshot.id or -1,
                )
                script_files.append(ScriptFile(script=script, file=file))

        return script_files
