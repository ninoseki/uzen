from app.factories.dns_records import DnsRecordFactory
from app.models.snapshots import Snapshot
from app.schemas.domain import DomainInformation
from app.services.whois import Whois


class DomainInformationFactory:
    @staticmethod
    async def from_hostname(hostname: str) -> DomainInformation:
        whois = Whois.whois(hostname)
        records = await DnsRecordFactory.from_hostname(hostname)
        snapshots = await Snapshot.find_by_hostname(hostname)
        return DomainInformation(
            hostname=hostname, whois=whois, dns_records=records, snapshots=snapshots
        )
