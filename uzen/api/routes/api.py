from fastapi import APIRouter

from uzen.api.routes import matches, rules, snapshots, urlscan, yara

api_router = APIRouter()
api_router.include_router(matches.router, prefix="/matches", tags=["Matches"])
api_router.include_router(rules.router, prefix="/rules", tags=["Rules"])
api_router.include_router(snapshots.router, prefix="/snapshots", tags=["Snapshots"])
api_router.include_router(urlscan.router, prefix="/import", tags=["Import"])
api_router.include_router(yara.router, prefix="/yara", tags=["YARA"])
