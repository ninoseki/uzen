import asyncio
import itertools

from uzen.models.classifications import Classification
from uzen.models.dns_records import DnsRecord
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot
from uzen.schemas.utils import EnrichmentResults
from uzen.tasks import AbstractTask
from uzen.tasks.classifications import ClassificationTask
from uzen.tasks.dns_records import DnsRecordTask
from uzen.tasks.scripts import ScriptTask


class EnrichmentTask(AbstractTask):
    def __init__(self, snapshot: Snapshot, insert_to_db: bool = True):
        self.tasks = [
            asyncio.create_task(ClassificationTask.process(snapshot, insert_to_db)),
            asyncio.create_task(DnsRecordTask.process(snapshot, insert_to_db)),
            asyncio.create_task(ScriptTask.process(snapshot, insert_to_db)),
        ]

    async def _process(self) -> EnrichmentResults:
        completed, pending = await asyncio.wait(self.tasks)
        results = list(itertools.chain(*[t.result() for t in completed]))

        scripts = []
        classifications = []
        dns_records = []
        for result in results:
            if isinstance(result, Classification):
                classifications.append(result)
            elif isinstance(result, DnsRecord):
                dns_records.append(result)
            elif isinstance(result, Script):
                scripts.append(result)

        return EnrichmentResults(
            classifications=classifications, dns_records=dns_records, scripts=scripts
        )

    @classmethod
    async def process(
        cls, snapshot: Snapshot, insert_to_db: bool = True
    ) -> EnrichmentResults:
        instance = cls(snapshot, insert_to_db)
        return await instance.safe_process()
