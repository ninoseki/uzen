import datetime
from typing import cast

import httpx

from app import dataclasses, models
from app.utils.hash import calculate_sha256


class URLScan:
    HOST = "urlscan.io"
    BASE_URL = f"https://{HOST}"

    def __init__(self, uuid: str):
        self.uuid = uuid

    async def body(self) -> str:
        url = f"{self.BASE_URL}/dom/{self.uuid}/"
        async with httpx.AsyncClient() as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.text

    async def screenshot(self) -> bytes:
        url = f"{self.BASE_URL}/screenshots/{self.uuid}.png"
        async with httpx.AsyncClient() as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.content

    async def result(self) -> dict:
        url = f"{self.BASE_URL}/api/v1/result/{self.uuid}/"
        async with httpx.AsyncClient() as client:
            r = await client.get(url)
            r.raise_for_status()
            return cast(dict, r.json())

    @classmethod
    async def import_as_snapshot(cls, uuid: str) -> dataclasses.SnapshotResult:
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

        time = cast(str, result.get("task", {}).get("time"))
        created_at = datetime.datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%fZ")

        html_content = await instance.body()
        html = models.HTML(id=calculate_sha256(html_content), content=html_content)

        snapshot = models.Snapshot(
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
            created_at=created_at,
            request={"urlscan.io": uuid},
        )

        screenshot = await instance.screenshot()

        return dataclasses.SnapshotResult(
            screenshot=screenshot,
            snapshot=snapshot,
            html=html,
            script_files=[],
            whois=None,
            certificate=None,
        )
