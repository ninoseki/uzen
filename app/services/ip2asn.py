from typing import Dict

import httpx
from async_lru import alru_cache

from app.core import settings


class IP2ASN:
    @staticmethod
    @alru_cache()
    async def lookup(ip_address: str) -> Dict[str, str]:
        if settings.IP2ASN_WEB_SERVICE_URL == "":
            return {}

        async with httpx.AsyncClient(
            base_url=settings.IP2ASN_WEB_SERVICE_URL, timeout=5.0
        ) as client:
            path = f"/v1/as/ip/{ip_address}"

            try:
                res = await client.get(path)
            except httpx.HTTPError:
                return {}

            data = res.json()

            asn = "AS" + str(data.get("as_number", ""))
            country_code = data.get("as_country_code", "")
            description = data.get("as_description", "")
            return {
                "ip_address": ip_address,
                "asn": asn,
                "country_code": country_code,
                "description": description,
            }
