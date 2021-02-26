from pydantic import BaseModel, ValidationError
from pydantic.networks import AnyHttpUrl


class UrlModel(BaseModel):
    url: AnyHttpUrl


def is_ip_address(ip_address: str) -> bool:
    try:
        model = UrlModel(url=f"http://{ip_address}")
        return model.url.host_type in ["ipv4", "ipv6"]
    except ValidationError:
        return False


def is_domain(domain: str) -> bool:
    if len(domain.split(".")) == 1:
        return False

    try:
        model = UrlModel(url=f"http://{domain}")
        return model.url.host_type in ["domain", "int_domain"]
    except ValidationError:
        return False
