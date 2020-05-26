from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from loguru import logger

from uzen.api.api import api_router
from uzen.core import settings
from uzen.core.events import create_start_app_handler, create_stop_app_handler


def create_app():
    logger.add(
        settings.LOG_FILE, level=settings.LOG_LEVEL, backtrace=settings.LOG_BACKTRACE
    )

    app = FastAPI(debug=settings.DEBUG, title=settings.PROJECT_NAME,)
    # add middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # add event handlers
    app.add_event_handler("startup", create_start_app_handler(app))
    app.add_event_handler("shutdown", create_stop_app_handler(app))

    # add routes
    app.include_router(api_router, prefix="/api")
    app.mount("/static", StaticFiles(directory="frontend/dist/static"), name="static")
    app.mount("/", StaticFiles(html=True, directory="frontend/dist/"), name="index")

    return app


app = create_app()
