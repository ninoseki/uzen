import sys

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings, Secret

config = Config(".env")

# general settings
PROJECT_NAME: str = config("PROJECT_NAME", default="uzen")

DEBUG: bool = config("DEBUG", cast=bool, default=False)
TESTING: bool = config("TESTING", cast=bool, default=False)

GLOBAL_API_KEY: str = config("GLOBAL_API_KEY", default="uzen")

# log settings
LOG_FILE = config("LOG_FILE", default=sys.stderr)
LOG_LEVEL: str = config("LOG_LEVEL", cast=str, default="DEBUG")
LOG_BACKTRACE: bool = config("LOG_BACKTRACE", cast=bool, default=True)

# database settings
DATABASE_URL: str = config("DATABASE_URL", cast=str, default="sqlite://:memory:")
APP_MODELS = config("APP_MODELS", cast=CommaSeparatedStrings, default="app.models",)

# Minio settings
MINIO_ENDPOINT: str = config("MINIO_ENDPOINT", cast=str, default="localhost:9000")
MINIO_ACCESS_KEY: str = config("MINIO_ACCESS_KEY", cast=str, default="")
MINIO_SECRET_KEY: str = config("MINIO_SECRET_KEY", cast=str, default="")
MINIO_SECURE: str = config("MINIO_SECURE", cast=bool, default=False)

# API keys
GOOGLE_SAFE_BROWSING_API_KEY: str = config(
    "GOOGLE_SAFE_BROWSING_API_KEY", cast=Secret, default=""
)

VIRUSTOTAL_API_KEY: str = config("VIRUSTOTAL_API_KEY", cast=Secret, default="")
