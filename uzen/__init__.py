from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles
from tortoise import Tortoise
import logging

from uzen.endpoints.snapshots import (
    SnapshotList,
    SnapshotGet,
    SnapshotPost,
    SnapshotDelete,
    SnapshotCount,
)
from uzen.endpoints.test import TestSetup, TestTearDown
from uzen.endpoints.yara import YaraScan
from uzen.endpoints.urlscan import URLScanPost

from uzen import settings


routes = [
    Mount(
        "/api/snapshots",
        name="snapshots",
        routes=[
            Route("/", SnapshotList, methods=["GET"]),
            Route("/", SnapshotPost, methods=["POST"]),
            Route("/{id:int}", SnapshotGet, methods=["GET"]),
            Route("/{id:int}", SnapshotDelete, methods=["DELETE"]),
            Route("/count", SnapshotCount, methods=["GET"]),
        ],
    ),
    Mount(
        "/api/yara", name="yara", routes=[Route("/scan", YaraScan, methods=["POST"]),],
    ),
    Mount(
        "/api/import",
        name="import",
        routes=[Route("/{uuid:str}", URLScanPost, methods=["POST"]),],
    ),
    Mount(
        "/api/test",
        name="test",
        routes=[
            Route("/setup", TestSetup, methods=["GET"]),
            Route("/teardown", TestTearDown, methods=["GET"]),
        ],
    ),
    Mount("/", app=StaticFiles(html=True, directory="dist")),
    Mount("/static", app=StaticFiles(directory="dist/static")),
]


async def http_exception(request, exc):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


exception_handlers = {HTTPException: http_exception}


def create_app(debug=settings.DEBUG):
    return Starlette(debug=debug, routes=routes, exception_handlers=exception_handlers)


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
