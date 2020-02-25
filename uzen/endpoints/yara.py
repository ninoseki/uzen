from json import JSONDecodeError
from starlette.endpoints import HTTPEndpoint
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR
import yara


from uzen.models import Snapshot
from uzen.browser import Browser
from uzen.yara import Yara


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
                status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            )

        snapshots = await Snapshot.all()
        matched_snapshots = []
        for snapshot in snapshots:
            matches = yara_scanner.scan(snapshot.body)
            if len(matches) > 0:
                matched_snapshots.append(snapshot)

        return JSONResponse(
            {"snapshots": [snapshot.to_dict() for snapshot in matched_snapshots]}
        )
