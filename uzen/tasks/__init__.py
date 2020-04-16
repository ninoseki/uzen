from typing import List, Union

from loguru import logger

from uzen.models.classifications import Classification
from uzen.models.dns_records import DnsRecord
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot


class AbstractTask:
    async def _process(self):
        raise NotImplementedError()

    async def safe_process(self):
        try:
            return await self._process()
        except Exception as e:
            logger.error(e)


class EnrichmentTask(AbstractTask):
    def __init__(self, snapshot: Snapshot, insert_to_db: bool = True):
        self.snapshot = snapshot
        self.insert_to_db = insert_to_db

    async def _process(
        self,
    ) -> Union[List[Script], List[DnsRecord], List[Classification]]:
        raise NotImplementedError()

    async def safe_process(
        self,
    ) -> Union[List[Script], List[DnsRecord], List[Classification]]:
        try:
            return await self._process()
        except Exception as e:
            f"Failed to process {self.__class__.__name__} task. URL: {self.snapshot.url} / Error: {e}"

        return []

    @classmethod
    async def process(
        cls, snapshot: Snapshot, insert_to_db: bool = True
    ) -> Union[List[Script], List[DnsRecord], List[Classification]]:
        instance = cls(snapshot, insert_to_db)
        return await instance.safe_process()
