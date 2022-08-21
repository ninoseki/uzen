from functools import lru_cache

from bs4 import BeautifulSoup


@lru_cache(maxsize=256)
def parse_html(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")
