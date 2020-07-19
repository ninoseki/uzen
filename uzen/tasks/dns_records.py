from typing import List

from loguru import logger

from uzen.factories.dns_records import DnsRecordFactory
from uzen.models.dns_records import DnsRecord
from uzen.tasks import EnrichmentTask


class DnsRecordTask(EnrichmentTask):
    async def _process(self) -> List[DnsRecord]:
        logger.debug(f"Fetch DNS records from {self.snapshot.hostname}")
        records = await DnsRecordFactory.from_snapshot(self.snapshot)
        if self.insert_to_db:
            await DnsRecord.bulk_create(records)

        return records
