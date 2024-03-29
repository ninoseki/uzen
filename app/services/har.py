import base64
from typing import List, Optional

from app import dataclasses, models
from app.dataclasses.har import HAR, Content, Entry, Request
from app.utils.hash import sha256


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


def find_main_entry(har: HAR) -> Optional[Entry]:
    for entry in har.log.entries:
        if entry.response.redirect_url == "":
            return entry

    return None


def find_request(har: HAR) -> Optional[Request]:
    main_entry = find_main_entry(har)
    if main_entry:
        return main_entry.request

    return None


def get_text(content: Content) -> str:
    if content.encoding == "base64":
        encoded_text = str(content.text)
        return base64.b64decode(encoded_text).decode("utf-8", "replace")

    return str(content.text)


def find_script_files(har: HAR) -> List[dataclasses.ScriptFile]:
    script_files: List[dataclasses.ScriptFile] = []

    for entry in har.log.entries:
        url = entry.request.url
        ip_address = entry.server_ip_address

        content = entry.response.content
        if not content:
            continue

        if is_js_content_type(content.mime_type):
            text = get_text(content)
            file_id = sha256(text)

            script = models.Script(url=url, ip_address=ip_address, file_id=file_id)
            file = models.File(id=file_id, content=text)
            script_files.append(dataclasses.ScriptFile(script=script, file=file))

    return script_files


def find_stylesheet_files(har: HAR) -> List[dataclasses.StylesheetFile]:
    stylesheet_files: List[dataclasses.StylesheetFile] = []

    for entry in har.log.entries:
        url = entry.request.url
        ip_address = entry.server_ip_address

        content = entry.response.content
        if not content:
            continue

        if is_stylesheet_content_type(content.mime_type):
            text = get_text(content)
            file_id = sha256(text)

            stylesheet = models.Stylesheet(
                url=url, ip_address=ip_address, file_id=file_id
            )
            file = models.File(id=file_id, content=text)
            stylesheet_files.append(
                dataclasses.StylesheetFile(stylesheet=stylesheet, file=file)
            )

    return stylesheet_files


class HARReader:
    def __init__(self, har: HAR):
        self.har: HAR = har

    def find_script_files(self) -> List[dataclasses.ScriptFile]:
        return find_script_files(self.har)

    def find_stylesheet_files(self) -> List[dataclasses.StylesheetFile]:
        return find_stylesheet_files(self.har)

    def find_request(self) -> Optional[Request]:
        return find_request(self.har)
