from typing import List

from loguru import logger

from app import models
from app.arq.tasks.helpers.abstract import EnrichmentHelper
from app.factories.dns_record import DnsRecordFactory


class DnsRecordHelper(EnrichmentHelper):
    async def _process(self) -> List[models.DnsRecord]:
        logger.debug(f"Fetch DNS records from {self.snapshot.hostname}")
        records = await DnsRecordFactory.from_snapshot(self.snapshot)
        if self.insert_to_db:
            await models.DnsRecord.bulk_create(records)

        return records
