from dataclasses import dataclass, field
from typing import List, Optional

from dataclasses_json import config, dataclass_json
from stringcase import camelcase


@dataclass_json
@dataclass
class Browser:
    name: str
    version: str
    comment: Optional[str] = None


@dataclass_json
@dataclass
class Creator:
    name: str
    version: str
    comment: Optional[str] = None


@dataclass_json(letter_case=camelcase)
@dataclass
class Cache:
    before_request: Optional[dict] = None
    after_request: Optional[dict] = None
    comment: Optional[str] = None


@dataclass_json(letter_case=camelcase)
@dataclass
class Request:
    method: str
    url: str
    http_version: str
    cookies: List[dict]
    headers: List[dict]
    query_string: List[dict]
    headers_size: int
    body_size: int
    post_data: Optional[dict] = None
    comment: Optional[str] = None


@dataclass_json(letter_case=camelcase)
@dataclass
class Content:
    size: int
    compression: Optional[int] = None
    mime_type: Optional[str] = None
    text: Optional[str] = None
    encoding: Optional[str] = None
    comment: Optional[str] = None


@dataclass_json(letter_case=camelcase)
@dataclass
class Response:
    status: int
    status_text: str
    http_version: str
    cookies: List[dict]
    headers: List[dict]
    content: Content
    headers_size: int
    body_size: int
    redirect_url: str = field(metadata=config(field_name="redirectURL"))
    comment: Optional[str] = None


@dataclass_json
@dataclass
class Timings:
    send: int
    wait: float
    receive: int
    blocked: Optional[int] = None
    dns: Optional[float] = None
    connect: Optional[float] = None
    ssl: Optional[float] = None
    comment: Optional[str] = None


@dataclass_json(letter_case=camelcase)
@dataclass
class Entry:
    started_date_time: str
    time: int
    request: Request
    response: Response
    cache: Cache
    timings: Timings
    pageref: Optional[str] = None
    server_ip_address: Optional[str] = field(
        default=None, metadata=config(field_name="serverIPAddress")
    )
    comment: Optional[str] = None


@dataclass_json(letter_case=camelcase)
@dataclass
class PageTimings:
    on_content_load: Optional[int] = None
    on_load: Optional[int] = None
    comment: Optional[str] = None


@dataclass_json(letter_case=camelcase)
@dataclass
class Page:
    started_date_time: str
    id: str
    title: str
    page_timings: PageTimings
    comment: Optional[str] = None


@dataclass_json
@dataclass
class Log:
    version: str
    creator: Creator
    browser: Browser
    pages: List[Page]
    entries: List[Entry]
    comment: Optional[str] = None


@dataclass_json
@dataclass
class HAR:
    log: Log
