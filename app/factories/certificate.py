from app import dataclasses, models


class CertificateFactory:
    @staticmethod
    def from_dataclass(certificate: dataclasses.Certificate) -> models.Certificate:
        return models.Certificate(
            id=certificate.fingerprint,
            content=certificate.text,
            not_after=certificate.not_after,
            not_before=certificate.not_before,
            issuer=certificate.issuer,
            subject=certificate.subject,
        )
