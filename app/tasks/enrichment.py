from functools import partial
from typing import cast

import aiometer

from app.models.classifications import Classification
from app.models.dns_records import DnsRecord
from app.models.snapshots import Snapshot
from app.schemas.utils import EnrichmentResults
from app.tasks import AbstractAsyncTask
from app.tasks.classifications import ClassificationTask
from app.tasks.dns_records import DnsRecordTask


class EnrichmentTasks(AbstractAsyncTask):
    def __init__(
        self, snapshot: Snapshot, insert_to_db: bool = True,
    ):
        self.tasks = [
            partial(ClassificationTask.process, snapshot, insert_to_db),
            partial(DnsRecordTask.process, snapshot, insert_to_db),
        ]

    async def _process(self) -> EnrichmentResults:
        results = await aiometer.run_all(self.tasks)

        classifications = []
        dns_records = []
        for result in results:
            if isinstance(result, Classification):
                classifications.append(result)
            elif isinstance(result, DnsRecord):
                dns_records.append(result)

        return EnrichmentResults(
            classifications=classifications, dns_records=dns_records,
        )

    @classmethod
    async def process(
        cls, snapshot: Snapshot, insert_to_db: bool = True
    ) -> EnrichmentResults:
        instance = cls(snapshot, insert_to_db)
        results = await instance.safe_process()
        return cast(EnrichmentResults, results)
