from app import models, schemas
from app.factories.dns_record import DnsRecordFactory
from app.services.whois import Whois


class DomainFactory:
    @staticmethod
    async def from_hostname(hostname: str) -> schemas.Domain:
        whois = Whois.whois(hostname)
        records = await DnsRecordFactory.from_hostname(hostname)
        snapshots = await models.Snapshot.find_by_hostname(hostname)
        return schemas.Domain(
            hostname=hostname, whois=whois, dns_records=records, snapshots=snapshots
        )
