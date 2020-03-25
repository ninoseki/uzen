from fastapi import APIRouter

from uzen.api.routes import (
    classifications,
    dns_records,
    snapshots,
    urlscan,
    yara,
    scripts,
)

api_router = APIRouter()
api_router.include_router(
    classifications.router, prefix="/classifications", tags=["Classifications"]
)
api_router.include_router(
    dns_records.router, prefix="/dns_records", tags=["DNS records"]
)
api_router.include_router(scripts.router, prefix="/scripts", tags=["Scripts"])
api_router.include_router(snapshots.router, prefix="/snapshots", tags=["Snapshots"])
api_router.include_router(urlscan.router, prefix="/import", tags=["Import"])
api_router.include_router(yara.router, prefix="/yara", tags=["YARA"])
