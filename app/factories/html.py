from niteru.html_parser import parse_html

from app import models
from app.utils.hash import sha256, ssdeep


class HTMLFactory:
    @staticmethod
    def from_str(html: str) -> models.HTML:
        html_id = sha256(html)
        ssdeep_ = ssdeep(html)
        parsed = parse_html(html)

        return models.HTML(
            id=html_id,
            content=html,
            ssdeep=ssdeep_,
            tags=parsed.tags,
            classes=parsed.classes,
        )
