import base64
import json
from dataclasses import dataclass
from functools import partial
from typing import List, Optional, cast

import aiometer
import httpx

from app import models
from app.core import settings


@dataclass
class Result:
    name: str
    malicious: bool
    note: Optional[str] = None


async def gsb_lookup(client: httpx.AsyncClient, url: str) -> Optional[Result]:
    if settings.GOOGLE_SAFE_BROWSING_API_KEY == "":
        return None

    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    data = {
        "client": {"clientId": "pysafe", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "THREAT_TYPE_UNSPECIFIED",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    paramas = {"key": str(settings.GOOGLE_SAFE_BROWSING_API_KEY)}
    headers = {"Content-type": "application/json"}

    try:
        res = await client.post(
            api_url, data=json.dumps(data), params=paramas, headers=headers
        )
        res.raise_for_status()
    except httpx.RequestError:
        return None

    data = res.json()
    matches = data.get("matches", [])
    malicious = len(matches) > 0

    return Result(name="Google SafeBrowsing", malicious=malicious)


async def virustotal_lookup(client: httpx.AsyncClient, url: str) -> Optional[Result]:
    if settings.VIRUSTOTAL_API_KEY == "":
        return None

    id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{id}"
    headers = {"x-apikey": str(settings.VIRUSTOTAL_API_KEY)}

    try:
        res = await client.get(api_url, headers=headers)
        res.raise_for_status()
    except httpx.HTTPError:
        return None

    data = res.json().get("data", {})
    attributes = data.get("attributes", {})
    last_analysis_stats = cast(dict, attributes.get("last_analysis_stats", {}))

    total = 0
    malicious = 0
    for key, value in last_analysis_stats.items():
        value = int(value)

        if key == "malicious":
            malicious = value

        total += value

    note = f"{malicious} / {total}"
    return Result(name="VirusTotal", malicious=malicious >= 5, note=note)


async def bulk_query(url: str) -> List[Optional[Result]]:
    async with httpx.AsyncClient() as client:
        jobs = [
            partial(gsb_lookup, client, url),
            partial(virustotal_lookup, client, url),
        ]
        return await aiometer.run_all(jobs)


class ClassificationFactory:
    @staticmethod
    async def from_snapshot(snapshot: models.Snapshot) -> List[models.Classification]:
        classifications: List[models.Classification] = []

        results = await bulk_query(snapshot.url)
        for result in results:
            if result is not None:
                classifications.append(
                    models.Classification(
                        name=result.name,
                        malicious=result.malicious,
                        note=result.note,
                        snapshot_id=snapshot.id or -1,
                    )
                )

        return classifications
