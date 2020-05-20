from typing import Dict

import httpx
from async_lru import alru_cache


class IPInfo:
    HOST = "ipinfo.io"
    BASE_URL = f"https://{HOST}"

    def __init__(self):
        self.client = httpx.AsyncClient()

    @alru_cache()
    async def info(self, ip_address: str) -> Dict[str, str]:
        url = f"{self.BASE_URL}/{ip_address}/json"
        r = await self.client.get(url)
        r.raise_for_status()
        return r.json()

    @classmethod
    async def get_info(cls, ip_address: str) -> Dict[str, str]:
        obj = cls()
        return await obj.info(ip_address)
