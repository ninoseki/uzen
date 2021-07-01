import httpx

from app import schemas


async def query_to_ipinfo():
    async with httpx.AsyncClient(base_url="https://ipinfo.io") as client:
        res = await client.get("/json")
        res.raise_for_status()

        return res.json()


class StatusFactory:
    @staticmethod
    async def from_ipinfo() -> schemas.Status:
        data = await query_to_ipinfo()
        ip = data.get("ip", "")
        country = data.get("country", "")

        return schemas.Status(ip_address=ip, country_code=country)
