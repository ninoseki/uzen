import base64
from typing import Dict, List, Optional

from app import dataclasses, models
from app.dataclasses.har import HAR, Entry
from app.utils.hash import calculate_sha256


def is_js_content_type(content_type: str) -> bool:
    types = ["application/javascript", "text/javascript"]
    for type_ in types:
        if content_type.startswith(type_):
            return True
    return False


def is_stylesheet_content_type(content_type: str) -> bool:
    types = ["text/css"]
    for type_ in types:
        if content_type.startswith(type_):
            return True
    return False


def find_main_entry(har: HAR) -> Optional[Entry]:
    for entry in har.log.entries:
        if entry.response.redirect_url == "":
            return entry


def find_request(har: HAR):
    main_entry = find_main_entry(har)
    return main_entry.request


def find_script_files(har: HAR) -> None:
    script_files: List[dataclasses.ScriptFile] = []

    for entry in har.log.entries:
        url = entry.request.url
        content = entry.response.content
        if not content:
            continue

        if is_js_content_type(content.mime_type):
            encoded_text = content.text
            text = base64.b64decode(encoded_text).decode()
            sha256 = calculate_sha256(text)

            script = models.Script(url=url, file_id=sha256)
            file = models.File(id=sha256, content=text)
            script_files.append(dataclasses.ScriptFile(script=script, file=file))

    return script_files


def find_stylesheet_files(har: HAR) -> None:
    stylesheet_files: List[dataclasses.StylesheetFile] = []

    for entry in har.log.entries:
        url = entry.request.url
        content = entry.response.content
        if not content:
            continue

        if is_stylesheet_content_type(content.mime_type):
            encoded_text = content.text
            text = base64.b64decode(encoded_text).decode()
            sha256 = calculate_sha256(text)

            stylesheet = models.Stylesheet(url=url, file_id=sha256)
            file = models.File(id=sha256, content=text)
            stylesheet_files.append(
                dataclasses.StylesheetFile(stylesheet=stylesheet, file=file)
            )

    return stylesheet_files


class HarBuilder:
    @staticmethod
    def from_dict(
        data: dict, events: List[dataclasses.ResponseReceivedEvent] = []
    ) -> dataclasses.HAR:
        har: dataclasses.HAR = dataclasses.HAR.from_dict(data)

        # url -> ip_address table
        memo: Dict[str, str] = {}
        for event in events:
            key = event.response.url
            value = event.response.remote_ip_address
            memo[key] = value

        # set an IP address as a comment
        for entry in har.log.entries:
            url = entry.request.url
            entry.response.comment = memo.get(url)

        return har


class HarReader:
    def __init__(self, har: HAR):
        self.har: HAR = har

    def find_script_files(self) -> List[dataclasses.ScriptFile]:
        return find_script_files(self.har)

    def find_stylesheet_files(self) -> List[dataclasses.StylesheetFile]:
        return find_stylesheet_files(self.har)

    def find_request(self) -> dict:
        return find_request(self.har)
