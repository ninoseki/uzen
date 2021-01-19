from abc import ABC, abstractmethod
from typing import List, Union

from loguru import logger

from app.models.classification import Classification
from app.models.dns_record import DnsRecord
from app.models.script import Script
from app.models.snapshot import Snapshot


class AbstractAsyncTask(ABC):
    @abstractmethod
    async def _process(self):
        raise NotImplementedError()

    async def safe_process(self):
        try:
            return await self._process()
        except Exception as e:
            logger.error(
                f"Failed to process {self.__class__.__name__} task. Error: {e}"
            )


class AbstractSyncTask(ABC):
    @abstractmethod
    def _process(self):
        raise NotImplementedError()

    def safe_process(self):
        try:
            return self._process()
        except Exception as e:
            logger.error(
                f"Failed to process {self.__class__.__name__} task. Error: {e}"
            )


class EnrichmentTask(AbstractAsyncTask):
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
            logger.error(
                f"Failed to process {self.__class__.__name__} task. URL: {self.snapshot.url} / Error: {e}"
            )

        return []

    @classmethod
    async def process(
        cls, snapshot: Snapshot, insert_to_db: bool = True
    ) -> Union[List[Script], List[DnsRecord], List[Classification]]:
        instance = cls(snapshot, insert_to_db)
        return await instance.safe_process()
