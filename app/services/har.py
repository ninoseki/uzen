import base64
from typing import List, Optional

from playwright_har_tracer.dataclasses.har import Entry, Har, Request

from app import dataclasses, models
from app.utils.hash import calculate_sha256


def is_js_content_type(content_type: Optional[str]) -> bool:
    if content_type is None:
        return False

    types = ["application/javascript", "text/javascript"]
    for type_ in types:
        if content_type.startswith(type_):
            return True

    return False


def is_stylesheet_content_type(content_type: Optional[str]) -> bool:
    if content_type is None:
        return False

    types = ["text/css"]
    for type_ in types:
        if content_type.startswith(type_):
            return True

    return False


def find_main_entry(har: Har) -> Optional[Entry]:
    for entry in har.log.entries:
        if entry.response.redirect_url == "":
            return entry

    return None


def find_request(har: Har) -> Optional[Request]:
    main_entry = find_main_entry(har)
    if main_entry:
        return main_entry.request

    return None


def find_script_files(har: Har) -> List[dataclasses.ScriptFile]:
    script_files: List[dataclasses.ScriptFile] = []

    for entry in har.log.entries:
        url = entry.request.url
        content = entry.response.content
        if not content:
            continue

        if is_js_content_type(content.mime_type):
            encoded_text = str(content.text)
            text = base64.b64decode(encoded_text).decode()
            sha256 = calculate_sha256(text)

            script = models.Script(url=url, file_id=sha256)
            file = models.File(id=sha256, content=text)
            script_files.append(dataclasses.ScriptFile(script=script, file=file))

    return script_files


def find_stylesheet_files(har: Har) -> List[dataclasses.StylesheetFile]:
    stylesheet_files: List[dataclasses.StylesheetFile] = []

    for entry in har.log.entries:
        url = entry.request.url
        content = entry.response.content
        if not content:
            continue

        if is_stylesheet_content_type(content.mime_type):
            encoded_text = str(content.text)
            text = base64.b64decode(encoded_text).decode()
            sha256 = calculate_sha256(text)

            stylesheet = models.Stylesheet(url=url, file_id=sha256)
            file = models.File(id=sha256, content=text)
            stylesheet_files.append(
                dataclasses.StylesheetFile(stylesheet=stylesheet, file=file)
            )

    return stylesheet_files


class HarReader:
    def __init__(self, har: Har):
        self.har: Har = har

    def find_script_files(self) -> List[dataclasses.ScriptFile]:
        return find_script_files(self.har)

    def find_stylesheet_files(self) -> List[dataclasses.StylesheetFile]:
        return find_stylesheet_files(self.har)

    def find_request(self) -> Optional[Request]:
        return find_request(self.har)
