from typing import List, Optional

import httpx
from requests_html import HTML

from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot
from uzen.services.utils import calculate_sha256


def normalize_source(url: str, source: str) -> str:
    if source.startswith("http://") or source.startswith("https://"):
        return source

    return f"{url}{source}"


def get_script_sources(url: str, body: str) -> List[str]:
    html = HTML(html=body)

    sources: List[str] = []
    for script in html.find("script"):
        source = script.attrs.get("src")
        if source is not None:
            sources.append(normalize_source(url, source))

    return list(set(sources))


async def get_script_content(source: str) -> Optional[str]:
    try:
        client = httpx.AsyncClient()
        res = await client.get(source)
        res.raise_for_status()
        return res.text
    except httpx.HTTPError:
        return None


class ScriptBuilder:
    @staticmethod
    async def build_from_snapshot(snapshot: Snapshot) -> List[Script]:
        sources = get_script_sources(url=snapshot.url, body=snapshot.body)
        scripts = []
        for source in sources:
            content = await get_script_content(source)
            if content is None:
                continue

            script = Script(
                url=source,
                content=content,
                sha256=calculate_sha256(content),
                # insert a dummy ID if a snapshot doesn't have ID
                snapshot_id=snapshot.id or -1,
            )
            scripts.append(script)
        return scripts
