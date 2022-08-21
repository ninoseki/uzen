from typing import TYPE_CHECKING, Optional

from tortoise.exceptions import NoValuesFetched

from app import schemas

if TYPE_CHECKING:
    from app.models.snapshot import Snapshot


def build_rules(snapshot: "Snapshot") -> list[schemas.Rule]:
    try:
        return [rule.to_model() for rule in snapshot.rules]
    except NoValuesFetched:
        return []


def build_tags(snapshot: "Snapshot") -> list[schemas.Tag]:
    try:
        return [tag.to_model() for tag in snapshot.tags]
    except NoValuesFetched:
        return []


def build_scripts(snapshot: "Snapshot") -> list[schemas.Script]:
    try:
        return [script.to_model() for script in snapshot.scripts]
    except NoValuesFetched:
        return []


def build_stylesheets(snapshot: "Snapshot") -> list[schemas.Stylesheet]:
    try:
        return [stylesheet.to_model() for stylesheet in snapshot.stylesheets]
    except NoValuesFetched:
        return []


def build_dns_records(snapshot: "Snapshot") -> list[schemas.DnsRecord]:
    try:
        return [record.to_model() for record in snapshot.dns_records]
    except NoValuesFetched:
        return []


def build_classifications(snapshot: "Snapshot") -> list[schemas.Classification]:
    try:
        return [
            classification.to_model() for classification in snapshot.classifications
        ]
    except NoValuesFetched:
        return []


def build_certificate(snapshot: "Snapshot") -> Optional[schemas.Certificate]:
    if snapshot.certificate is not None:
        return snapshot.certificate.to_model()

    return None


def build_whois(snapshot: "Snapshot") -> Optional[schemas.Whois]:
    if snapshot.whois is not None:
        return snapshot.whois.to_model()

    return None


class SnapshotFactory:
    @staticmethod
    def from_model(snapshot: "Snapshot") -> schemas.Snapshot:
        return schemas.Snapshot(
            id=snapshot.id,
            url=snapshot.url,
            submitted_url=snapshot.submitted_url,
            status=snapshot.status,
            hostname=snapshot.hostname,
            ip_address=snapshot.ip_address,
            asn=snapshot.asn,
            country_code=snapshot.country_code,
            response_headers=snapshot.response_headers,
            request_headers=snapshot.request_headers,
            processing=snapshot.processing,
            created_at=snapshot.created_at,
            html=snapshot.html.to_model(),
            whois=build_whois(snapshot),
            certificate=build_certificate(snapshot),
            rules=build_rules(snapshot),
            tags=build_tags(snapshot),
            scripts=build_scripts(snapshot),
            stylesheets=build_stylesheets(snapshot),
            dns_records=build_dns_records(snapshot),
            classifications=build_classifications(snapshot),
        )
