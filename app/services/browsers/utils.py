from typing import List, Optional, cast

from playwright_har_tracer.dataclasses.har import Har

from app import dataclasses, models
from app.factories.certificate import CertificateFactory
from app.factories.har import HarFactory
from app.factories.html import HTMLFactory
from app.factories.whois import WhoisFactory
from app.services.certificate import Certificate
from app.services.har import HarReader
from app.services.whois import Whois
from app.utils.network import (
    get_asn_by_ip_address,
    get_country_code_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)


def find_ip_address(url: str, har: Optional[Har]) -> str:
    """Find an IP address of a URL from HAR

    Args:
        url (str): URL
        har (Optional[Har]): HAR

    Returns:
        str: IP address
    """
    if har is not None:
        for entry in har.log.entries:
            if entry.request.url == url and entry.server_ip_address is not None:
                return entry.server_ip_address

    hostname = cast(str, get_hostname_from_url(url))
    ip_address = cast(str, get_ip_address_by_hostname(hostname))
    return ip_address


async def build_snapshot_model_wrapper(
    submitted_url: str,
    snapshot: dataclasses.Snapshot,
) -> dataclasses.SnapshotModelWrapper:
    url = snapshot.url
    har = snapshot.har

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

    snapshot_model = models.Snapshot(
        url=url,
        submitted_url=submitted_url,
        status=snapshot.status,
        request_headers=snapshot.request_headers,
        response_headers=snapshot.response_headers,
        hostname=hostname,
        ip_address=ip_address,
        asn=asn,
        country_code=country_code,
        ignore_https_errors=snapshot.options.ignore_https_errors,
    )
    html = HTMLFactory.from_str(snapshot.html)
    whois = WhoisFactory.from_dataclass(whois_data) if whois_data else None
    certificate = (
        CertificateFactory.from_dataclass(certificate_data)
        if certificate_data
        else None
    )
    har_model = HarFactory.from_dataclass(har) if har else None

    return dataclasses.SnapshotModelWrapper(
        screenshot=snapshot.screenshot,
        html=html,
        certificate=certificate,
        whois=whois,
        snapshot=snapshot_model,
        script_files=script_files,
        stylesheet_files=stylesheet_files,
        har=har_model,
    )
