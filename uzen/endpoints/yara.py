from json import JSONDecodeError
from starlette.endpoints import HTTPEndpoint
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR
import asyncio
import math
import yara
from loguru import logger

from uzen.browser import Browser
from uzen.models import Snapshot
from uzen.services.snapshot_search import SnapshotSearcher
from uzen.services.yara_scanner import YaraScanner


class YaraScan(HTTPEndpoint):
    async def post(self, request) -> JSONResponse:
        try:
            payload = await request.json()
            source = payload["source"]
        except JSONDecodeError:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail="cannot parse request body"
            )
        except KeyError:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail="source is required"
            )

        try:
            yara_scanner = YaraScanner(source)
        except yara.Error as e:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            )

        params = request.query_params
        snapshots = await yara_scanner.scan_snapshots(params)
        return JSONResponse(
            {"snapshots": [snapshot.to_dict()
                           for snapshot in snapshots]}
        )
