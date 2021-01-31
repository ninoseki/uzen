from functools import lru_cache
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app import dataclasses
from app.dataclasses.utils import HttpResource


def extract_base_path(path: str) -> str:
    """Extract base path from a path (or remove a filename from the path)

    Arguments:
        path {str} -- A path e.g. /foo/bar/index.html

    Returns:
        str -- A base path (e.g. /foo/bar/)
    """
    parts = path.split("/")
    return "/".join(parts[:-1])


def convert_to_absolute_url(url: str, source: str) -> str:
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


@lru_cache()
def parse_html(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def get_script_urls(url: str, html: str,) -> List[str]:
    """Get a list of script urls

    Arguments:
        url {str} -- A URL
        html {str} -- An HTTP response body

    Returns:
        List[str] -- A list of script urls
    """
    html = parse_html(html)

    urls: List[str] = []
    for element in html.find_all("script"):
        src: str = element.attrs.get("src")
        if src is not None:
            urls.append(convert_to_absolute_url(url, src))

    return list(set(urls))


def get_stylesheet_urls(url: str, html: str,) -> List[str]:
    """Get a list of stylesheet urls

    Arguments:
        url {str} -- A URL
        html {str} -- An HTTP response body

    Returns:
        List[str] -- A list of stylesheet urls
    """
    html = parse_html(html)

    urls: List[str] = []
    for element in html.find_all("link"):
        href: Optional[str] = element.attrs.get("href")
        type_: Optional[str] = element.attrs.get("type")
        if href is not None and type_ is not None:
            urls.append(convert_to_absolute_url(url, href))

    return list(set(urls))


async def get_http_resource(
    client: httpx.AsyncClient, url: str, headers: Dict
) -> Optional[dataclasses.HttpResource]:
    """Get an http resource

    Arguments:
        source {str} -- A source of a script (an absolute URL)

    Returns:
        Optional[ScriptContent] -- A fetched result
    """
    try:
        res = await client.get(url, headers=headers)
        res.raise_for_status()
        content_type = res.headers.get("content-type", None)
        return HttpResource(url=url, content=res.text, content_type=content_type)
    except httpx.HTTPError:
        return None
