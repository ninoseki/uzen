import sys
from typing import Optional, TextIO

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings, Secret

from app.core.datastructures import DatabaseURL

config = Config(".env")

# general settings
PROJECT_NAME: str = config("PROJECT_NAME", default="uzen")

DEBUG: bool = config("DEBUG", cast=bool, default=False)
TESTING: bool = config("TESTING", cast=bool, default=False)

# secret key settings
SECRET_API_KEY: Secret = config("SECRET_API_KEY", cast=Secret, default="uzen")

# log settings
LOG_FILE: TextIO = config("LOG_FILE", default=sys.stderr)
LOG_LEVEL: str = config("LOG_LEVEL", cast=str, default="DEBUG")
LOG_BACKTRACE: bool = config("LOG_BACKTRACE", cast=bool, default=True)

# database settings
DATABASE_URL: DatabaseURL = config(
    "DATABASE_URL", cast=DatabaseURL, default="sqlite://:memory:"
)
APP_MODELS: CommaSeparatedStrings = config(
    "APP_MODELS",
    cast=CommaSeparatedStrings,
    default="app.models",
)

# Minio settings
MINIO_ENDPOINT: str = config("MINIO_ENDPOINT", cast=str, default="localhost:9000")
MINIO_ACCESS_KEY: Secret = config("MINIO_ACCESS_KEY", cast=Secret, default="")
MINIO_SECRET_KEY: Secret = config("MINIO_SECRET_KEY", cast=Secret, default="")
MINIO_SECURE: bool = config("MINIO_SECURE", cast=bool, default=False)

# Redis settings
REDIS_URL: DatabaseURL = config(
    "REDIS_URL", cast=DatabaseURL, default="redis://localhost:6379"
)

# ARQ settings
ARQ_MAX_JOBS: int = config("ARQ_MAX_JOBS", cast=int, default=10)
ARQ_REDIS_CONN_TIMEOUT: int = config("ARQ_REDIS_CONN_TIMEOUT", cast=int, default=10)
ARQ_REDIS_CONN_RETRIES: int = config("ARQ_REDIS_CONN_RETRIES", cast=int, default=5)
ARQ_REDIS_CONN_RETRY_DELAY: int = config(
    "ARQ_REDIS_CONN_RETRY_DELAY", cast=int, default=1
)

# Redis cache settings
REDIS_CACHE_URL: DatabaseURL = config(
    "REDIS_URL", cast=DatabaseURL, default="redis://localhost:6379"
)
REDIS_CACHE_NAMESPACE: str = config("REDIS_CACHE_NAMESPACE", cast=str, default="cache")

# IP to ASN web service settings
IP2ASN_WEB_SERVICE_URL: str = config("IP2ASN_WEB_SERVICE_URL", cast=str, default="")

# API keys
GOOGLE_SAFE_BROWSING_API_KEY: Secret = config(
    "GOOGLE_SAFE_BROWSING_API_KEY", cast=Secret, default=""
)
VIRUSTOTAL_API_KEY: Secret = config("VIRUSTOTAL_API_KEY", cast=Secret, default="")

# Sentry
SENTRY_DNS: Optional[Secret] = config("SENTRY_DNS", cast=Secret, default=None)
SENTRY_TRACES_SAMPLE_RATE: float = config(
    "SENTRY_TRACES_SAMPLE_RATE", cast=float, default=0.1
)
