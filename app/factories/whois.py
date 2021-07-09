from d8s_hashes import sha256

from app import dataclasses, models


class WhoisFactory:
    @staticmethod
    def from_dataclass(whois: dataclasses.Whois) -> models.Whois:
        return models.Whois(
            id=sha256(whois.content),
            content=whois.content,
            created=whois.created,
            updated=whois.updated,
            expires=whois.expires,
            registrar=whois.registrar,
            registrant_organization=whois.registrant_organization,
            registrant_name=whois.registrant_name,
        )
