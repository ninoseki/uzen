import json
from functools import lru_cache
from io import BytesIO

from minio import Minio
from minio.helpers import ObjectWriteResult

from app.core import settings


def get_client() -> Minio:
    return Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
    )


@lru_cache()
def create_bucket_if_not_exists(client: Minio, bucket_name: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            },
        ],
    }

    found = client.bucket_exists(bucket_name)
    if not found:
        client.make_bucket(bucket_name)

    client.set_bucket_policy(bucket_name, json.dumps(policy))


def upload_screenshot(
    bucket_name: str, file_name: str, screenshot: bytes
) -> ObjectWriteResult:
    client = get_client()

    create_bucket_if_not_exists(client, bucket_name)

    data = BytesIO(screenshot)
    length = len(screenshot)
    object_name = f"{file_name}.png"

    return client.put_object(
        bucket_name, object_name, data, length, content_type="image/png"
    )
