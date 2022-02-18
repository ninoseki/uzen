from datetime import datetime
from typing import Optional, Union

from app import dataclasses, models
from app.utils.hash import sha256


def normalize_datetime_like_value(
    value: Optional[Union[datetime, str]]
) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value

    return None


class WhoisFactory:
    @staticmethod
    def from_dataclass(whois: dataclasses.Whois) -> models.Whois:
        created = normalize_datetime_like_value(whois.created)
        updated = normalize_datetime_like_value(whois.updated)
        expires = normalize_datetime_like_value(whois.expires)

        return models.Whois(
            id=sha256(whois.content),
            content=whois.content,
            created=created,
            updated=updated,
            expires=expires,
            registrar=whois.registrar,
            registrant_organization=whois.registrant_organization,
            registrant_name=whois.registrant_name,
        )
