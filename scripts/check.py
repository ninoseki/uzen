"""A script for checking general settings"""
import sys

import sqlite3
from pyppeteer import __chromium_revision__, __pyppeteer_home__
from pyppeteer.chromium_downloader import (
    check_chromium,
    chromium_executable,
)

sys.path = ["", ".."] + sys.path[1:]  # noqa

from uzen.core import settings


def check():
    print("[pyppeteer settings]")
    print(f"Chromium version: {__chromium_revision__}")
    print(f"Home drectory: {__pyppeteer_home__}")
    downloaded = "downloaded" if check_chromium() else "not downloaded"
    print(f"Executable: {chromium_executable()} ({downloaded})")

    print()

    print("[DB settings]")
    print(f"SQLite version: {sqlite3.sqlite_version}")
    print(f"SQLite Python library version: {sqlite3.version}")
    print(f"File path: {settings.DATABASE_URL}")


if __name__ == "__main__":
    check()
