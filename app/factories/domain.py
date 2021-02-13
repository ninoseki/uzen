from functools import partial

import aiometer

from app import models, schemas
from app.factories.dns_record import DnsRecordFactory
from app.services.whois import Whois


class DomainFactory:
    @staticmethod
    async def from_hostname(hostname: str) -> schemas.Domain:
        whois = Whois.whois(hostname)

        tasks = [
            partial(DnsRecordFactory.from_hostname, hostname),
            partial(models.Snapshot.find_by_hostname, hostname),
        ]
        records, snapshots = await aiometer.run_all(tasks)

        return schemas.Domain(
            hostname=hostname, whois=whois, dns_records=records, snapshots=snapshots
        )
