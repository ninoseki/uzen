from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from loguru import logger
from tortoise import Tortoise

from uzen import settings
from uzen.endpoints import api_router


def create_app():
    logger.add(
        settings.LOG_FILE,
        level=settings.LOG_LEVEL,
        backtrace=settings.LOG_BACKTRACE
    )

    app = FastAPI(
        debug=settings.DEBUG,
        title=settings.PROJECT_NAME,
    )

    app.include_router(api_router, prefix="/api")
    app.mount(
        "/static", StaticFiles(directory="frontend/dist/static"), name="static"
    )
    app.mount(
        "/", StaticFiles(html=True, directory="frontend/dist/"), name="index"
    )

    app.add_middleware(GZipMiddleware, minimum_size=1000)

    return app


app = create_app()


@app.on_event("startup")
async def on_startup() -> None:
    await Tortoise.init(
        db_url=settings.DATABASE_URL, modules={"models": settings.APP_MODELS}
    )
    await Tortoise.generate_schemas()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    await Tortoise.close_connections()
