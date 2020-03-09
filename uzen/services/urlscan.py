import base64
import datetime

import requests

from uzen.models.snapshots import Snapshot


class URLScan:
    HOST = "urlscan.io"
    BASE_URL = f"https://{HOST}"

    def __init__(self, uuid: str):
        self.session = requests.Session()
        self.uuid = uuid

    def body(self) -> str:
        url = f"{self.BASE_URL}/dom/{self.uuid}/"
        r = self.session.get(url)
        r.raise_for_status()
        return r.text

    def screenshot(self) -> str:
        url = f"{self.BASE_URL}/screenshots/{self.uuid}.png"
        r = self.session.get(url)
        r.raise_for_status()
        return str(base64.b64encode(r.content), "utf-8")

    def result(self) -> dict:
        url = f"{self.BASE_URL}/api/v1/result/{self.uuid}/"
        r = self.session.get(url)
        r.raise_for_status()
        return r.json()

    @classmethod
    def import_as_snapshot(cls, uuid: str) -> Snapshot:
        """Import urlscan.io scan as a snapshot

        Arguments:
            uuid {str} -- Scan ID

        Returns:
            Snapshot -- Snapshot ORM instance
        """
        instance = cls(uuid)
        result = instance.result()

        requests = result.get("data", {}).get("requests", [])
        response = {}
        for request in requests:
            tmp = request.get("response", {}).get("response", {})
            if tmp.get("status") == 200:
                response = tmp
                break

        headers = response.get("headers", {})
        body = instance.body()
        sha256 = result.get("lists", {}).get("hashes", [])[0]
        screenshot = instance.screenshot()
        time = result.get("task", {}).get("time")
        created_at = datetime.datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%fZ")

        asn = result.get("page", {}).get("asn")
        asnname = result.get("page", {}).get("asnname")
        return Snapshot(
            url=result.get("page", {}).get("url"),
            status=200,
            hostname=result.get("page", {}).get("domain"),
            ip_address=result.get("page", {}).get("ip"),
            asn=f"{asn} {asnname}",
            server=result.get("page", {}).get("server"),
            content_type=headers.get("Content-Type") or headers.get("content-type"),
            content_length=headers.get("Content-Length")
            or headers.get("content-length"),
            headers=headers,
            body=body,
            sha256=sha256,
            screenshot=screenshot,
            created_at=created_at,
        )
