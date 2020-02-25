from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings

config = Config(".env")

DEBUG = config("DEBUG", cast=bool, default=False)
TESTING = config("DEBUG", cast=bool, default=False)

DATABASE_URL = config("DATABASE_URL", cast=str)
APP_MODELS = config("APP_MODELS", cast=CommaSeparatedStrings)
