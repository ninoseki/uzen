from typing import Literal

from .ulid import ULID

WaitUntilType = Literal["domcontentloaded", "load", "networkidle"]


__all__ = ["ULID", "WaitUntilType"]
