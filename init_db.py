from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings
from tortoise import Tortoise, run_async
import contextlib
import os
import sys

from uzen.datastructures import DatabaseURL

config = Config(".env")

DATABASE_URL = config("DATABASE_URL", cast=DatabaseURL)
APP_MODELS = config("APP_MODELS", cast=CommaSeparatedStrings)


async def init():
    msg = "".join(
        [
            f"This command will create a new database: {DATABASE_URL.database}, ",
            "any existing database will be DESTROYED...\n\nEnter 'yes' to continue.\n",
        ]
    )
    confirm = input(msg)
    if confirm != "yes":
        sys.exit()

    with contextlib.suppress(FileNotFoundError):
        os.remove(DATABASE_URL.database)

    await Tortoise.init(db_url=str(DATABASE_URL), modules={"models": APP_MODELS})
    await Tortoise.generate_schemas()


if __name__ == "__main__":
    run_async(init())
