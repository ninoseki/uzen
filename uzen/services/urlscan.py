import base64
import datetime
import httpx

from uzen.models.snapshots import Snapshot


class URLScan:
    HOST = "urlscan.io"
    BASE_URL = f"https://{HOST}"

    def __init__(self, uuid: str):
        self.client = httpx.AsyncClient()
        self.uuid = uuid

    async def body(self) -> str:
        url = f"{self.BASE_URL}/dom/{self.uuid}/"
        r = await self.client.get(url)
        r.raise_for_status()
        return r.text

    async def screenshot(self) -> str:
        url = f"{self.BASE_URL}/screenshots/{self.uuid}.png"
        r = await self.client.get(url)
        r.raise_for_status()
        return str(base64.b64encode(r.content), "utf-8")

    async def result(self) -> dict:
        url = f"{self.BASE_URL}/api/v1/result/{self.uuid}/"
        r = await self.client.get(url)
        r.raise_for_status()
        return r.json()

    @classmethod
    async def import_as_snapshot(cls, uuid: str) -> Snapshot:
        """Import urlscan.io scan as a snapshot

        Arguments:
            uuid {str} -- Scan ID

        Returns:
            Snapshot -- Snapshot ORM instance
        """
        instance = cls(uuid)
        result = await instance.result()

        requests = result.get("data", {}).get("requests", [])
        response = {}
        for request in requests:
            tmp = request.get("response", {}).get("response", {})
            if tmp.get("status") == 200:
                response = tmp
                break

        url = result.get("page", {}).get("url")
        submitted_url = result.get("task", {}).get("url")
        hostname = result.get("page", {}).get("domain")
        ip_address = result.get("page", {}).get("ip")
        asn = result.get("page", {}).get("asn")
        asnname = result.get("page", {}).get("asnname")

        headers = response.get("headers", {})
        server = result.get("page", {}).get("server")
        content_type = headers.get("Content-Type") or headers.get("content-type")
        content_length = headers.get("Content-Length") or headers.get("content-length")

        body = await instance.body()
        sha256 = result.get("lists", {}).get("hashes", [])[0]
        screenshot = await instance.screenshot()
        time = result.get("task", {}).get("time")
        created_at = datetime.datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%fZ")

        return Snapshot(
            url=url,
            submitted_url=submitted_url,
            status=200,
            hostname=hostname,
            ip_address=ip_address,
            asn=f"{asn} {asnname}",
            server=server,
            content_type=content_type,
            content_length=content_length,
            headers=headers,
            body=body,
            sha256=sha256,
            screenshot=screenshot,
            created_at=created_at,
        )
