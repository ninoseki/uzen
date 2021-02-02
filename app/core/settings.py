import sys

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings, Secret

config = Config(".env")

PROJECT_NAME: str = config("PROJECT_NAME", default="uzen")

DEBUG: bool = config("DEBUG", cast=bool, default=False)
TESTING: bool = config("TESTING", cast=bool, default=False)

LOG_FILE = config("LOG_FILE", default=sys.stderr)
LOG_LEVEL: str = config("LOG_LEVEL", cast=str, default="DEBUG")
LOG_BACKTRACE: bool = config("LOG_BACKTRACE", cast=bool, default=True)

DATABASE_URL: str = config("DATABASE_URL", cast=str, default="sqlite://:memory:")
APP_MODELS = config("APP_MODELS", cast=CommaSeparatedStrings, default="app.models",)

GOOGLE_SAFE_BROWSING_API_KEY: str = config(
    "GOOGLE_SAFE_BROWSING_API_KEY", cast=Secret, default=""
)

BROWSER_WS_ENDPOINT: str = config("BROWSER_WS_ENDPOINT", cast=str, default="")

HTTPX_FALLBACK: bool = config("HTTPX_FALLBACK", cast=bool, default=True)

MINIO_ENDPOINT: str = config("MINIO_ENDPOINT", cast=str, default="localhost:9000")
MINIO_ACCESS_KEY: str = config("MINIO_ACCESS_KEY", cast=str, default="")
MINIO_SECRET_KEY: str = config("MINIO_SECRET_KEY", cast=str, default="")
MINIO_SECURE: str = config("MINIO_SECURE", cast=bool, default=False)
