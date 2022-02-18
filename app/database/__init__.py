from tortoise import Tortoise

from app.core import settings


async def init_db() -> None:
    await Tortoise.init(
        db_url=str(settings.DATABASE_URL), modules={"models": settings.APP_MODELS}
    )
    await Tortoise.generate_schemas()
