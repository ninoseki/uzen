from abc import ABC, abstractstaticmethod
from typing import List, Optional, cast

from app import dataclasses, models
from app.factories.har import HarFactory
from app.services.certificate import Certificate
from app.services.har import HarReader
from app.services.whois import Whois
from app.utils.hash import calculate_sha256
from app.utils.network import (
    get_asn_by_ip_address,
    get_country_code_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)


def find_ip_address(url: str, events: List[dataclasses.ResponseReceivedEvent]):
    for event in events:
        if event.response.url == url:
            return event.response.remote_ip_address

    hostname = cast(str, get_hostname_from_url(url))
    ip_address = cast(str, get_ip_address_by_hostname(hostname))
    return ip_address


async def build_snapshot_result(
    submitted_url: str,
    browsing_result: dataclasses.BrowsingResult,
    har: Optional[dataclasses.HAR] = None,
) -> dataclasses.SnapshotResult:

    url = browsing_result.url
    ip_address = find_ip_address(url, browsing_result.response_received_events)
    hostname = cast(str, get_hostname_from_url(url))
    asn = await get_asn_by_ip_address(ip_address) or ""
    country_code = await get_country_code_by_ip_address(ip_address) or ""

    script_files: List[dataclasses.ScriptFile] = []
    stylesheet_files: List[dataclasses.StylesheetFile] = []

    if har:
        har_reader = HarReader(har)
        script_files = har_reader.find_script_files()
        stylesheet_files = har_reader.find_stylesheet_files()

    certificate = Certificate.load_from_url(url)

    whois_result = await Whois.lookup(hostname)
    whois_result = cast(dataclasses.Whois, whois_result)

    snapshot = models.Snapshot(
        url=url,
        submitted_url=submitted_url,
        status=browsing_result.status,
        request_headers=browsing_result.request_headers,
        response_headers=browsing_result.response_headers,
        hostname=hostname,
        ip_address=ip_address,
        asn=asn,
        country_code=country_code,
        ignore_https_erros=browsing_result.options.ignore_https_errors,
    )
    html = models.HTML(
        id=calculate_sha256(browsing_result.html), content=browsing_result.html
    )
    whois = (
        models.Whois(
            id=calculate_sha256(whois_result.content),
            content=whois_result.content,
            created=whois_result.created,
            updated=whois_result.updated,
            expires=whois_result.expires,
            registrar=whois_result.registrar,
            registrant_organization=whois_result.registrant_organization,
            registrant_name=whois_result.registrant_name,
        )
        if whois_result
        else None
    )
    certificate = (
        models.Certificate(
            id=certificate.fingerprint,
            content=certificate.text,
            not_after=certificate.not_after,
            not_before=certificate.not_before,
            issuer=certificate.issuer,
            subject=certificate.subject,
        )
        if certificate
        else None
    )
    har = HarFactory.from_dataclass(har) if har else None

    return dataclasses.SnapshotResult(
        screenshot=browsing_result.screenshot,
        html=html,
        certificate=certificate,
        whois=whois,
        snapshot=snapshot,
        script_files=script_files,
        stylesheet_files=stylesheet_files,
        har=har,
    )


class AbstractBrowser(ABC):
    @abstractstaticmethod
    async def take_snapshot(
        url: str, options: dataclasses.BrowsingOptions,
    ) -> dataclasses.SnapshotResult:
        raise NotImplementedError()
