import requests
import base64

from uzen.models import Snapshot


class URLScan:
    HOST = "urlscan.io"
    BASE_URL = f"https://{HOST}"

    def __init__(self, uuid: str):
        self.session = requests.Session()
        self.uuid = uuid

    def body(self):
        url = f"{self.BASE_URL}/dom/{self.uuid}/"
        r = self.session.get(url)
        r.raise_for_status()
        return r.text

    def screenshot(self):
        url = f"{self.BASE_URL}/screenshots/{self.uuid}.png"
        r = self.session.get(url)
        r.raise_for_status()
        return str(base64.b64encode(r.content), "utf-8")

    def result(self):
        url = f"{self.BASE_URL}/api/v1/result/{self.uuid}/"
        r = self.session.get(url)
        r.raise_for_status()
        return r.json()

    @classmethod
    def import_as_snapshot(cls, uuid: str) -> Snapshot:
        instance = cls(uuid)
        result = instance.result()

        requests = result.get("data", {}).get("requests", [])
        response = {}
        if len(requests) > 0:
            first = requests[0]
            response = first.get("response", {}).get("response", {})

        headers = response.get("headers", {})
        body = instance.body()
        screenshot = instance.screenshot()
        return Snapshot(
            url=result.get("page", {}).get("url"),
            status=200,
            hostname=result.get("page", {}).get("domain"),
            ip_address=result.get("page", {}).get("ip"),
            server=result.get("page", {}).get("server"),
            content_type=headers.get("content-type"),
            content_length=headers.get("content-length"),
            headers=headers,
            body=body,
            screenshot=screenshot,
        )
