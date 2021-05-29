from abc import ABC, abstractstaticmethod
from typing import List, Optional, cast

from playwright_har_tracer.dataclasses.har import Har

from app import dataclasses, models
from app.factories.certificate import CertificateFactory
from app.factories.har import HarFactory
from app.factories.whois import WhoisFactory
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


def find_ip_address(url: str, har: Optional[Har]) -> str:
    if har is not None:
        for entry in har.log.entries:
            if (
                entry.request.url == url
                and entry.response._remote_ip_address is not None
            ):
                return entry.response._remote_ip_address

    hostname = cast(str, get_hostname_from_url(url))
    ip_address = cast(str, get_ip_address_by_hostname(hostname))
    return ip_address


async def build_snapshot_result(
    submitted_url: str,
    browsing_result: dataclasses.BrowsingResult,
) -> dataclasses.SnapshotResult:
    url = browsing_result.url
    har = browsing_result.har

    ip_address = find_ip_address(url, har)
    hostname = cast(str, get_hostname_from_url(url))
    asn = await get_asn_by_ip_address(ip_address) or ""
    country_code = await get_country_code_by_ip_address(ip_address) or ""

    script_files: List[dataclasses.ScriptFile] = []
    stylesheet_files: List[dataclasses.StylesheetFile] = []

    if har is not None:
        har_reader = HarReader(har)
        script_files = har_reader.find_script_files()
        stylesheet_files = har_reader.find_stylesheet_files()

    certificate_data = Certificate.load_from_url(url)

    whois_data = await Whois.lookup(hostname)
    whois_data = cast(dataclasses.Whois, whois_data)

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
    whois = WhoisFactory.from_dataclass(whois_data) if whois_data else None
    certificate = (
        CertificateFactory.from_dataclass(certificate_data)
        if certificate_data
        else None
    )
    har_model = HarFactory.from_dataclass(har) if har else None

    return dataclasses.SnapshotResult(
        screenshot=browsing_result.screenshot,
        html=html,
        certificate=certificate,
        whois=whois,
        snapshot=snapshot,
        script_files=script_files,
        stylesheet_files=stylesheet_files,
        har=har_model,
    )


class AbstractBrowser(ABC):
    @staticmethod
    @abstractstaticmethod
    async def take_snapshot(
        url: str,
        options: dataclasses.BrowsingOptions,
    ) -> dataclasses.SnapshotResult:
        raise NotImplementedError()
