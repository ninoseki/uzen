from typing import List

from loguru import logger

from app.factories.dns_records import DnsRecordFactory
from app.models.dns_records import DnsRecord
from app.tasks import EnrichmentTask


class DnsRecordTask(EnrichmentTask):
    async def _process(self) -> List[DnsRecord]:
        logger.debug(f"Fetch DNS records from {self.snapshot.hostname}")
        records = await DnsRecordFactory.from_snapshot(self.snapshot)
        if self.insert_to_db:
            await DnsRecord.bulk_create(records)

        return records
