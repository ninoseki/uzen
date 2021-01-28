from fastapi import APIRouter

from app.api.endpoints import (
    devices,
    domain,
    hars,
    ip_address,
    matches,
    rules,
    screenshots,
    snapshots,
    urlscan,
    yara,
)

api_router = APIRouter()
api_router.include_router(devices.router, prefix="/devices", tags=["Device"])
api_router.include_router(domain.router, prefix="/domain", tags=["Domain"])
api_router.include_router(ip_address.router, prefix="/ip_address", tags=["IP address"])
api_router.include_router(matches.router, prefix="/matches", tags=["Matches"])
api_router.include_router(rules.router, prefix="/rules", tags=["Rules"])
api_router.include_router(
    screenshots.router, prefix="/screenshots", tags=["Screenshots"]
)
api_router.include_router(snapshots.router, prefix="/snapshots", tags=["Snapshots"])
api_router.include_router(urlscan.router, prefix="/import", tags=["Import"])
api_router.include_router(yara.router, prefix="/yara", tags=["YARA"])
api_router.include_router(hars.router, prefix="/hars", tags=["HAR"])
