from functools import partial

import aiometer

from app import models, schemas
from app.factories.dns_record import DnsRecordFactory
from app.services.whois import Whois


class DomainFactory:
    @staticmethod
    async def from_hostname(hostname: str) -> schemas.Domain:
        tasks = [
            partial(Whois.lookup, hostname),
            partial(DnsRecordFactory.from_hostname, hostname),
            partial(models.Snapshot.find_by_hostname, hostname),
        ]
        whois, records, snapshots = await aiometer.run_all(tasks)

        snapshots = [snapshot.to_model() for snapshot in snapshots]

        return schemas.Domain(
            hostname=hostname, whois=whois, dns_records=records, snapshots=snapshots
        )
