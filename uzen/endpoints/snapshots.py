from json import JSONDecodeError
from pyppeteer.errors import PyppeteerError
from starlette.endpoints import HTTPEndpoint
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.status import (
    HTTP_201_CREATED,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from tortoise.exceptions import DoesNotExist
import validators

from uzen.models import Snapshot
from uzen.browser import Browser


class SnapshotList(HTTPEndpoint):
    async def get(self, request) -> JSONResponse:
        params = request.query_params
        size = int(params.get("size", 100))
        offset = int(params.get("offset", 0))

        if "size" in params.keys() and "offset" not in params.keys():
            snapshots = await Snapshot.all().order_by("-created_at").limit(size)
        elif "offset" in params.keys():
            snapshots = await Snapshot.all().order_by("id").offset(offset).limit(size)
        else:
            snapshots = await Snapshot.all().order_by("created_at")

        return JSONResponse(
            {"snapshots": [snapshot.to_dict() for snapshot in snapshots]}
        )


class SnapshotGet(HTTPEndpoint):
    async def get(self, request) -> JSONResponse:
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
    async def get(self, request) -> JSONResponse:
        count = await Snapshot.all().count()
        return JSONResponse({"count": count})


class SnapshotPost(HTTPEndpoint):
    async def post(self, request) -> JSONResponse:
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

        if not validators.url(url):
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail=f"{url} is not a valid URL"
            )

        try:
            snapshot = await Browser.take_snapshot(url)
        except PyppeteerError as e:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            )

        await snapshot.save()
        return JSONResponse(
            {"snapshot": snapshot.to_dict()}, status_code=HTTP_201_CREATED
        )


class SnapshotDelete(HTTPEndpoint):
    async def delete(self, request) -> JSONResponse:
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
