from functools import lru_cache
from typing import List

from playwright.sync_api import sync_playwright
from pydantic import Field

from app.schemas.base import APIModel


class Viewport(APIModel):
    """View port"""

    width: int = Field(...)
    height: int = Field(...)


class DeviceDescriptor(APIModel):
    """Device descriptor"""

    user_agent: str = Field(...)
    viewport: Viewport = Field(...)
    device_scale_factor: float = Field(...)
    is_mobile: bool = Field(...)
    has_touch: bool = Field(...)


class Device(APIModel):
    """Device to be used with a browser"""

    name: str = Field(...)
    descriptor: DeviceDescriptor = Field(...)


@lru_cache(maxsize=1)
def get_devices() -> List[Device]:
    devices: List[Device] = []

    with sync_playwright() as playwright:
        for name, descriptor in playwright.devices.items():
            devices.append(Device.parse_obj({"name": name, "descriptor": descriptor}))

        return devices
