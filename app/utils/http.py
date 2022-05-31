from functools import lru_cache
from typing import Any, Dict, List, Optional

import httpx
from bs4 import BeautifulSoup

from app import dataclasses
from app.dataclasses.utils import HttpResource
from app.utils.url import url_base_form


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

    base_url = url_base_form(url).removesuffix("/")

    if source.startswith("/"):
        return f"{base_url}{source}"

    return f"{base_url}/{source}"


@lru_cache
def parse_html(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def get_script_urls(
    url: str,
    html: str,
) -> List[str]:
    """Get a list of script urls

    Arguments:
        url {str} -- A URL
        html {str} -- An HTTP response body

    Returns:
        List[str] -- A list of script urls
    """
    soup = parse_html(html)

    urls: List[str] = []
    for element in soup.find_all("script"):
        src: str = element.attrs.get("src")
        if src is not None:
            urls.append(convert_to_absolute_url(url, src))

    return list(set(urls))


def get_stylesheet_urls(
    url: str,
    html: str,
) -> List[str]:
    """Get a list of stylesheet urls

    Arguments:
        url {str} -- A URL
        html {str} -- An HTTP response body

    Returns:
        List[str] -- A list of stylesheet urls
    """
    soup = parse_html(html)

    urls: List[str] = []
    for element in soup.find_all("link"):
        href: Optional[str] = element.attrs.get("href")
        type_: Optional[str] = element.attrs.get("type")
        if href is not None and type_ is not None:
            urls.append(convert_to_absolute_url(url, href))

    return list(set(urls))


async def get_http_resource(
    client: httpx.AsyncClient, url: str, headers: Dict[str, Any]
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
