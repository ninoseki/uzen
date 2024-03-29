from fastapi import APIRouter

from app.api.endpoints import (
    api_keys,
    certificates,
    devices,
    domain,
    files,
    hars,
    htmls,
    ip_address,
    jobs,
    matches,
    rules,
    screenshots,
    similarity,
    snapshots,
    status,
    whois,
    yara,
)

api_router = APIRouter()

api_router.include_router(api_keys.router, prefix="/api_keys", tags=["API Key"])
api_router.include_router(
    certificates.router, prefix="/certificates", tags=["Certificate"]
)
api_router.include_router(devices.router, prefix="/devices", tags=["Device"])
api_router.include_router(domain.router, prefix="/domain", tags=["Domain"])
api_router.include_router(files.router, prefix="/files", tags=["Files"])
api_router.include_router(hars.router, prefix="/hars", tags=["HAR"])
api_router.include_router(htmls.router, prefix="/htmls", tags=["HTML"])
api_router.include_router(ip_address.router, prefix="/ip_address", tags=["IP address"])
api_router.include_router(jobs.router, prefix="/jobs", tags=["Jobs"])
api_router.include_router(matches.router, prefix="/matches", tags=["Matches"])
api_router.include_router(rules.router, prefix="/rules", tags=["Rules"])
api_router.include_router(
    screenshots.router, prefix="/screenshots", tags=["Screenshots"]
)
api_router.include_router(similarity.router, prefix="/similarity", tags=["Similarity"])
api_router.include_router(snapshots.router, prefix="/snapshots", tags=["Snapshots"])
api_router.include_router(status.router, prefix="/status", tags=["Status"])
api_router.include_router(whois.router, prefix="/whoises", tags=["Whois"])
api_router.include_router(yara.router, prefix="/yara", tags=["YARA"])
