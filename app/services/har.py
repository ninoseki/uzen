import base64
from typing import List, Optional

from app import dataclasses, models
from app.utils.hash import calculate_sha256


def is_js_content_type(content_type: str) -> bool:
    types = ["application/javascript", "text/javascript"]
    for type_ in types:
        if content_type.startswith(type_):
            return True
    return False


def find_main_entry(data: dict) -> Optional[dict]:
    log = data.get("log", {})
    entries = log.get("entries", [])
    for entry in entries:
        response = entry.get("response", {})
        redirecdt_url = response.get("redirectURL")
        if redirecdt_url == "":
            return entry


def find_request(data: dict):
    main_entry = find_main_entry(data)
    return main_entry.get("request", {})


def find_script_files(data: dict) -> None:
    script_files: List[dataclasses.ScriptFile] = []

    log = data.get("log", {})
    entries = log.get("entries", [])
    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        response = entry.get("response", {})
        content = response.get("content", {})
        if not content:
            continue

        content_type: str = content.get("mimeType", "")
        if is_js_content_type(content_type):
            encoded_text = content.get("text", "")
            text = base64.b64decode(encoded_text).decode()
            sha256 = calculate_sha256(text)

            script = models.Script(url=url, file_id=sha256)
            file = models.File(id=sha256, content=text)
            script_files.append(dataclasses.ScriptFile(script=script, file=file))

    return script_files


class HarReader:
    def __init__(self, data: dict):
        self.data = data

    def find_script_files(self) -> List[dataclasses.ScriptFile]:
        return find_script_files(self.data)

    def find_request(self) -> dict:
        return find_request(self.data)
