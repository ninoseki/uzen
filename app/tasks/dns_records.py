from typing import List

from loguru import logger

from app import models
from app.factories.dns_records import DnsRecordFactory
from app.tasks import EnrichmentTask


class DnsRecordTask(EnrichmentTask):
    async def _process(self) -> List[models.DnsRecord]:
        logger.debug(f"Fetch DNS records from {self.snapshot.hostname}")
        records = await DnsRecordFactory.from_snapshot(self.snapshot)
        if self.insert_to_db:
            await models.DnsRecord.bulk_create(records)

        return records
