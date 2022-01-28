import urllib.parse as urlparse


def normalize_url(url: str) -> str:
    """Normalize URL

    Arguments:
        url {str} -- A URL

    Returns:
        str -- A normalized URL
    """
    # remove string after "?" to comply with Pydantic AnyHttpUrl validation
    # e.g. http:/example.com/test.js?foo=bar to http://example.com/test.js
    splitted = url.split("?")
    return splitted[0]


def url_base_form(url: str) -> str:
    """Get the base URL without a path, query strings, or other junk."""
    parsed_url = urlparse.urlparse(url)
    return f"{parsed_url.scheme}://{parsed_url.netloc}/"
