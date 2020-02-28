from json import JSONDecodeError
from starlette.endpoints import HTTPEndpoint
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR
import asyncio
import math
import yara

from uzen.models import Snapshot
from uzen.browser import Browser
from uzen.yara import Yara

CHUNK_SIZE = 100
PARALLEL_LIMIT = 10
sem = asyncio.Semaphore(PARALLEL_LIMIT)


async def partial_scan(scanner, idx: int):
    with await sem:
        offset = idx * CHUNK_SIZE
        snapshots = await Snapshot.all().offset(offset).limit(CHUNK_SIZE).values("id", "body")
        matched_ids = []
        for snapshot in snapshots:
            id = snapshot.get("id")
            body = snapshot.get("body", "")
            matches = scanner.scan(body)
            if len(matches) > 0:
                matched_ids.append(id)

        return matched_ids


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
            yara_scanner = Yara(source)
        except yara.Error as e:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="failed to compile YARA rule"
            )

        # split snapshots into chunks and scan them in parallel
        count = await Snapshot.all().count()
        tasks = [
            partial_scan(yara_scanner, idx) for idx in range(math.ceil(count/CHUNK_SIZE))
        ]
        completed, pending = await asyncio.wait(tasks)
        results = [t.result() for t in completed]

        # flatten the results (ids)
        matched_ids = sum(results, [])
        matched_snapshots = await Snapshot.filter(id__in=matched_ids).all()
        return JSONResponse(
            {"snapshots": [snapshot.to_dict()
                           for snapshot in matched_snapshots]}
        )
