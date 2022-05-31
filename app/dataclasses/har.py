from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Union

import arrow
from dataclasses_json import LetterCase, Undefined
from dataclasses_json.api import DataClassJsonMixin
from dataclasses_json.cfg import config


class CustomizedDataClassJsonMixin(DataClassJsonMixin):
    dataclass_json_config = config(
        letter_case=LetterCase.CAMEL,
        undefined=Undefined.EXCLUDE,
        exclude=lambda f: f is None,
    )["dataclasses_json"]


def datetime_encoder(dt: Optional[datetime] = None) -> Optional[str]:
    if dt is None:
        return None

    arrw = arrow.get(dt)
    return arrw.isoformat()


def datetime_decoder(dt: Optional[str] = None) -> Optional[datetime]:
    if dt is None:
        return None

    arrw = arrow.get(dt)
    return arrw.datetime


@dataclass
class Browser(CustomizedDataClassJsonMixin):
    name: str
    version: str
    comment: Optional[str] = None


@dataclass
class Creator(CustomizedDataClassJsonMixin):
    name: str
    version: str
    comment: Optional[str] = None


@dataclass
class CacheState(CustomizedDataClassJsonMixin):
    last_access: str
    e_tag: str
    hit_count: int
    expires: Optional[str] = None


@dataclass
class Cache(CustomizedDataClassJsonMixin):
    before_request: Optional[CacheState] = None
    after_request: Optional[CacheState] = None
    comment: Optional[str] = None


@dataclass
class QueryParameter(CustomizedDataClassJsonMixin):
    name: str
    value: str


@dataclass
class Header(CustomizedDataClassJsonMixin):
    name: str
    value: str


@dataclass
class Cookie(CustomizedDataClassJsonMixin):
    name: str
    value: str
    path: Optional[str] = None
    domain: Optional[str] = None
    expires: Optional[datetime] = field(
        default=None,
        metadata=config(encoder=datetime_encoder, decoder=datetime_decoder),
    )
    http_only: bool = False
    secure: bool = False
    same_site: Optional[str] = None


@dataclass
class Param(CustomizedDataClassJsonMixin):
    name: str
    value: Optional[str] = None
    file_name: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class PostData(CustomizedDataClassJsonMixin):
    mime_type: str
    text: str
    params: List[Param] = field(default_factory=list)


@dataclass
class Request(CustomizedDataClassJsonMixin):
    method: str
    url: str
    http_version: str
    headers_size: int
    body_size: int

    post_data: Optional[PostData] = None
    comment: Optional[str] = None

    cookies: List[Cookie] = field(default_factory=list)
    headers: List[Header] = field(default_factory=list)
    query_string: List[QueryParameter] = field(default_factory=list)


@dataclass
class Content(CustomizedDataClassJsonMixin):
    size: int
    compression: Optional[int] = None
    mime_type: Optional[str] = None
    text: Optional[str] = None
    encoding: Optional[str] = None
    comment: Optional[str] = None


@dataclass
class Response(CustomizedDataClassJsonMixin):
    status: int
    status_text: str
    http_version: str
    content: Content
    headers_size: int
    body_size: int
    redirect_url: str = field(metadata=config(field_name="redirectURL"))

    comment: Optional[str] = None
    _transfer_size: Optional[int] = field(
        default=None, metadata=config(field_name="_transferSize")
    )

    cookies: List[Cookie] = field(default_factory=list)
    headers: List[Header] = field(default_factory=list)


@dataclass
class Timings(CustomizedDataClassJsonMixin):
    send: Union[int, float]
    wait: Union[int, float]
    receive: Union[int, float]
    blocked: Optional[Union[int, float]] = None
    dns: Optional[Union[int, float]] = None
    connect: Optional[Union[int, float]] = None
    ssl: Optional[Union[int, float]] = None
    comment: Optional[Union[int, float]] = None


@dataclass
class SecurityDetails(CustomizedDataClassJsonMixin):
    protocol: Optional[str] = None
    subject_name: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[int] = None
    valid_to: Optional[int] = None


@dataclass
class Entry(CustomizedDataClassJsonMixin):
    started_date_time: datetime = field(
        metadata=config(encoder=datetime_encoder, decoder=datetime_decoder)
    )
    time: Union[int, float]
    request: Request
    response: Response
    cache: Cache
    timings: Timings
    pageref: Optional[str] = None
    server_ip_address: Optional[str] = field(
        default=None, metadata=config(field_name="serverIPAddress")
    )
    comment: Optional[str] = None

    _server_port: Optional[int] = field(
        default=None, metadata=config(field_name="_serverPort")
    )
    _security_details: Optional[SecurityDetails] = field(
        default=None, metadata=config(field_name="_securityDetails")
    )


@dataclass
class PageTimings(CustomizedDataClassJsonMixin):
    on_content_load: Union[int, float, None] = None
    on_load: Union[int, float, None] = None
    comment: Optional[str] = None


@dataclass
class Page(CustomizedDataClassJsonMixin):
    started_date_time: datetime = field(
        metadata=config(encoder=datetime_encoder, decoder=datetime_decoder)
    )
    id: str
    title: str
    page_timings: PageTimings
    comment: Optional[str] = None


@dataclass
class Log(CustomizedDataClassJsonMixin):
    version: str
    creator: Creator
    browser: Browser

    comment: Optional[str] = None

    pages: List[Page] = field(default_factory=list)
    entries: List[Entry] = field(default_factory=list)


@dataclass
class Har(CustomizedDataClassJsonMixin):
    log: Log
