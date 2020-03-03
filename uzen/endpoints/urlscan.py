from json import JSONDecodeError
from pyppeteer.errors import PyppeteerError
from starlette.endpoints import HTTPEndpoint
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.status import (
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
)
import requests

from uzen.models import Snapshot
from uzen.urlscan import URLScan


class URLScanPost(HTTPEndpoint):
    async def post(self, request: Request) -> JSONResponse:
        try:
            uuid = request.path_params["uuid"]
        except KeyError:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail="uuid is required"
            )

        try:
            snapshot = URLScan.import_as_snapshot(uuid)
        except requests.exceptions.HTTPError:
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND, detail=f"{uuid} is not found"
            )

        await snapshot.save()
        return JSONResponse(
            {"snapshot": snapshot.to_dict()}, status_code=HTTP_201_CREATED
        )
