import re

from pydantic import BaseModel, ValidationError
from pydantic.networks import AnyHttpUrl


class UrlModel(BaseModel):
    url: AnyHttpUrl


def is_ip_address(v: str) -> bool:
    try:
        model = UrlModel(url=f"http://{v}")
        return model.url.host_type in ["ipv4", "ipv6"]
    except ValidationError:
        return False


def is_domain(v: str) -> bool:
    if len(v.split(".")) == 1:
        return False

    try:
        model = UrlModel(url=f"http://{v}")
        return model.url.host_type in ["domain", "int_domain"]
    except ValidationError:
        return False


def is_asn(v: str) -> bool:
    return re.match(r"^AS\d+$", v) is not None


def is_network_address(v: str) -> bool:
    if is_ip_address(v):
        return True

    if is_domain(v):
        return True

    if is_asn(v):
        return True

    return False


def is_hash(v: str) -> bool:
    return re.match(r"^[a-f0-9]{64}$", v) is not None
