import sys

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings, Secret

config = Config(".env")

PROJECT_NAME = config("PROJECT_NAME", default="uzen")

DEBUG = config("DEBUG", cast=bool, default=False)
TESTING = config("TESTING", cast=bool, default=False)

LOG_FILE = config("LOG_FILE", default=sys.stderr)
LOG_LEVEL = config("LOG_LEVEL", cast=str, default="DEBUG")
LOG_BACKTRACE = config("LOG_BACKTRACE", cast=bool, default=True)

DATABASE_URL = config("DATABASE_URL", cast=str, default="sqlite://:memory:")
APP_MODELS = config(
    "APP_MODELS",
    cast=CommaSeparatedStrings,
    default="uzen.models.snapshots,uzen.models.scripts,uzen.models.dns_records,uzen.models.classifications",
)

GOOGLE_SAFE_BROWSING_API_KEY = config(
    "GOOGLE_SAFE_BROWSING_API_KEY", cast=Secret, default=""
)
