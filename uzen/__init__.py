from loguru import logger
from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles
from tortoise import Tortoise


from uzen.endpoints.snapshots import (
    SnapshotCount,
    SnapshotDelete,
    SnapshotGet,
    SnapshotList,
    SnapshotPost,
    SnapshotSearch,
)
from uzen.endpoints.yara import YaraScan, YaraOneshot
from uzen.endpoints.urlscan import URLScanPost

from uzen import settings


routes = [
    Mount(
        "/api/snapshots",
        name="snapshots",
        routes=[
            Route("/", SnapshotList, methods=["GET"]),
            Route("/search", SnapshotSearch, methods=["GET"]),
            Route("/", SnapshotPost, methods=["POST"]),
            Route("/{id:int}", SnapshotGet, methods=["GET"]),
            Route("/{id:int}", SnapshotDelete, methods=["DELETE"]),
            Route("/count", SnapshotCount, methods=["GET"]),
        ],
    ),
    Mount(
        "/api/yara", name="yara", routes=[
            Route("/scan", YaraScan, methods=["POST"]),
            Route("/oneshot", YaraOneshot, methods=["POST"]),
        ],
    ),
    Mount(
        "/api/import",
        name="import",
        routes=[Route("/{uuid:str}", URLScanPost, methods=["POST"]), ],
    ),
    Mount("/", app=StaticFiles(html=True, directory="frontend/dist")),
    Mount("/static", app=StaticFiles(directory="frontend/dist/static")),
]


async def http_exception(request, exc):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


exception_handlers = {HTTPException: http_exception}


middleware = [
    Middleware(GZipMiddleware, minimum_size=1000)
]


def create_app(debug=settings.DEBUG):
    logger.add(
        settings.LOG_FILE,
        level=settings.LOG_LEVEL,
        backtrace=settings.LOG_BACKTRACE
    )
    return Starlette(
        debug=debug,
        routes=routes,
        middleware=middleware,
        exception_handlers=exception_handlers,
    )


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
