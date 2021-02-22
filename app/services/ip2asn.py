from typing import Dict

import httpx
from aiocache import Cache, cached
from aiocache.serializers import JsonSerializer

from app.core import settings


class IP2ASN:
    @staticmethod
    @cached(ttl=60 * 10, cache=Cache.MEMORY, serializer=JsonSerializer())
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
