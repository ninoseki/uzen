from typing import Optional

import httpx
from aiocache import Cache, cached
from aiocache.serializers import PickleSerializer

from app import dataclasses
from app.core import settings


class IP2ASN:
    @staticmethod
    @cached(ttl=60 * 10, cache=Cache.MEMORY, serializer=PickleSerializer())
    async def lookup(ip_address: str) -> Optional[dataclasses.IP2ASNResponse]:
        if settings.IP2ASN_WEB_SERVICE_URL == "":
            return None

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
            return dataclasses.IP2ASNResponse(
                asn=asn,
                ip_address=ip_address,
                country_code=country_code,
                description=description,
            )
