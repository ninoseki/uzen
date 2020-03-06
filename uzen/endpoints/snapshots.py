from json import JSONDecodeError
from pyppeteer.errors import PyppeteerError
from starlette.endpoints import HTTPEndpoint
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.status import (
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from tortoise.exceptions import DoesNotExist
import validators

from uzen.browser import Browser
from uzen.models import Snapshot
from uzen.responses import ORJSONResponse as JSONResponse
from uzen.services.snapshot_search import SnapshotSearcher


class SnapshotList(HTTPEndpoint):
    async def get(self, request: Request) -> JSONResponse:
        params = request.query_params
        size = int(params.get("size", 100))
        offset = int(params.get("offset", 0))
        snapshots = await SnapshotSearcher.search({}, size=size, offset=offset)

        return JSONResponse(
            {"snapshots": [snapshot.to_dict() for snapshot in snapshots]}
        )


class SnapshotSearch(HTTPEndpoint):
    async def get(self, request: Request) -> JSONResponse:
        params = request.query_params

        size = params.get("size")
        if size is not None:
            size = int(size)
        offset = params.get("offset")
        if offset is not None:
            offset = int(offset)

        snapshots = await SnapshotSearcher.search(params, size=size, offset=offset)

        return JSONResponse(
            {"snapshots": [snapshot.to_dict() for snapshot in snapshots]}
        )


class SnapshotGet(HTTPEndpoint):
    async def get(self, request: Request) -> JSONResponse:
        try:
            id = request.path_params["id"]
        except KeyError:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail="id is required"
            )

        try:
            snapshot = await Snapshot.get(id=id)
        except DoesNotExist:
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND, detail=f"Snapshot:{id} is not found"
            )

        return JSONResponse({"snapshot": snapshot.to_dict()})


class SnapshotCount(HTTPEndpoint):
    async def get(self, request: Request) -> JSONResponse:
        params = request.query_params
        count = await SnapshotSearcher.search(params, count_only=True)
        return JSONResponse({"count": count})


class SnapshotPost(HTTPEndpoint):
    async def post(self, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
            url = payload["url"]
        except JSONDecodeError:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail="cannot parse request body"
            )
        except KeyError:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail="url is required"
            )

        user_agent = payload.get("user_agent")
        timeout = int(payload.get("timeout", 30000))
        ignore_https_errors = payload.get("ignore_https_errors", False)
        if not validators.url(url):
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail=f"{url} is not a valid URL"
            )

        try:
            snapshot = await Browser.take_snapshot(
                url,
                user_agent=user_agent,
                timeout=timeout,
                ignore_https_errors=ignore_https_errors
            )
        except PyppeteerError as e:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            )

        await snapshot.save()
        return JSONResponse(
            {"snapshot": snapshot.to_dict()}, status_code=HTTP_201_CREATED
        )


class SnapshotDelete(HTTPEndpoint):
    async def delete(self, request: Request) -> JSONResponse:
        try:
            id = request.path_params["id"]
        except KeyError:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail="id is required"
            )

        try:
            snapshot = await Snapshot.get(id=id)
        except DoesNotExist:
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND, detail=f"Snapshot:{id} is not found"
            )

        await snapshot.delete()
        return JSONResponse({}, status_code=HTTP_204_NO_CONTENT)
