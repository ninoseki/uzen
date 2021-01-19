from functools import partial
from typing import List, cast

import aiometer

from app import dataclasses, models
from app.tasks import AbstractAsyncTask
from app.tasks.classification import ClassificationTask
from app.tasks.dns_record import DnsRecordTask


class EnrichmentTasks(AbstractAsyncTask):
    def __init__(
        self, snapshot: models.Snapshot, insert_to_db: bool = True,
    ):
        self.tasks = [
            partial(ClassificationTask.process, snapshot, insert_to_db),
            partial(DnsRecordTask.process, snapshot, insert_to_db),
        ]

    async def _process(self) -> dataclasses.EnrichmentResults:
        results = await aiometer.run_all(self.tasks)

        classifications: List[models.Classification] = []
        dns_records: List[models.DnsRecord] = []
        for result in results:
            if isinstance(result, models.Classification):
                classifications.append(result)
            elif isinstance(result, models.DnsRecord):
                dns_records.append(result)

        return dataclasses.EnrichmentResults(
            classifications=classifications, dns_records=dns_records,
        )

    @classmethod
    async def process(
        cls, snapshot: models.Snapshot, insert_to_db: bool = True
    ) -> dataclasses.EnrichmentResults:
        instance = cls(snapshot, insert_to_db)
        results = await instance.safe_process()
        return cast(dataclasses.EnrichmentResults, results)
