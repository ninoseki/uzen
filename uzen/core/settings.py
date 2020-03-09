import sys

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings

config = Config(".env")

PROJECT_NAME = config("PROJECT_NAME", default="uzen")

DEBUG = config("DEBUG", cast=bool, default=False)
TESTING = config("TESTING", cast=bool, default=False)

LOG_FILE = config("LOG_FILE", default=sys.stderr)
LOG_LEVEL = config("LOG_LEVEL", cast=str, default="DEBUG")
LOG_BACKTRACE = config("LOG_BACKTRACE", cast=bool, default=True)

DATABASE_URL = config("DATABASE_URL", cast=str)
APP_MODELS = config("APP_MODELS", cast=CommaSeparatedStrings)
