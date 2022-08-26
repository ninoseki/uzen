from typing import List

from loguru import logger

from app import models
from app.arq.tasks.helpers.abstract import EnrichmentHelper
from app.factories.dns_record import DNSRecordFactory


class DNSRecordHelper(EnrichmentHelper):
    async def _process(self) -> List[models.DNSRecord]:
        logger.debug(f"Fetch DNS records from {self.snapshot.hostname}")
        records = await DNSRecordFactory.from_snapshot(self.snapshot)
        if self.insert_to_db:
            await models.DNSRecord.bulk_create(records)

        return records
