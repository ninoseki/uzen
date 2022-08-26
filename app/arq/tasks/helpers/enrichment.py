from functools import partial
from typing import List, cast

import aiometer

from app import dataclasses, models
from app.arq.tasks.helpers.abstract import AbstractAsyncHelper
from app.arq.tasks.helpers.classification import ClassificationHelper
from app.arq.tasks.helpers.dns_record import DnsRecordHelper


class EnrichmentHelpers(AbstractAsyncHelper):
    def __init__(
        self,
        snapshot: models.Snapshot,
        insert_to_db: bool = True,
    ):
        self.tasks = [
            partial(ClassificationHelper.process, snapshot, insert_to_db),
            partial(DnsRecordHelper.process, snapshot, insert_to_db),
        ]

    async def _process(self) -> dataclasses.Enrichments:
        results = await aiometer.run_all(self.tasks)

        classifications: List[models.Classification] = []
        dns_records: List[models.DnsRecord] = []
        for result in results:
            if isinstance(result, models.Classification):
                classifications.append(result)
            elif isinstance(result, models.DnsRecord):
                dns_records.append(result)

        return dataclasses.Enrichments(
            classifications=classifications,
            dns_records=dns_records,
        )

    @classmethod
    async def process(
        cls, snapshot: models.Snapshot, insert_to_db: bool = True
    ) -> dataclasses.Enrichments:
        instance = cls(snapshot, insert_to_db)
        results = await instance.process_with_error_handling()
        return cast(dataclasses.Enrichments, results)
