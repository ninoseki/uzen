import os
from io import BytesIO
from typing import Optional

import httpx

from uzen.core import settings
from uzen.services.minio import create_bucket_if_not_exists, get_client

SCREENSHOT_BUCKET_NAME: str = "uzen-screenshot"


def upload_screenshot(
    file_name: str, screenshot: Optional[bytes], bucket_name=SCREENSHOT_BUCKET_NAME
):
    if screenshot is None:
        return

    client = get_client()

    create_bucket_if_not_exists(client, bucket_name)

    data = BytesIO(screenshot)
    length = len(screenshot)
    object_name = f"{file_name}.png"

    return client.put_object(
        bucket_name, object_name, data, length, content_type="image/png"
    )


def get_screenshot_url(uuid: str, bucket_name=SCREENSHOT_BUCKET_NAME) -> str:
    scheme = "https" if settings.MINIO_SECURE else "http"
    return f"{scheme}://{settings.MINIO_ENDPOINT}/{bucket_name}/{uuid}.png"


def get_not_found_png() -> bytes:
    current_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(current_path, "../../frontend/dist/images/not-found.png")
    with open(path, "rb") as f:
        return f.read()


async def get_screenshot(uuid: str) -> bytes:
    url = get_screenshot_url(uuid)
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(url)
            res.raise_for_status()
            print(url)
            return res.content
    except httpx.HTTPError:
        return get_not_found_png()
