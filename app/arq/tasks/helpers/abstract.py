from abc import ABC, abstractmethod
from typing import Any, List, Union

from loguru import logger

from app.models.classification import Classification
from app.models.dns_record import DnsRecord
from app.models.script import Script
from app.models.snapshot import Snapshot


class AbstractAsyncHelper(ABC):
    @abstractmethod
    async def _process(self) -> Any:
        raise NotImplementedError()

    async def process_with_error_handling(self) -> Any:
        try:
            return await self._process()
        except Exception as e:
            logger.error(f"Failed to process {self.__class__.__name__} task.")
            logger.exception(e)


class EnrichmentHelper(AbstractAsyncHelper):
    def __init__(self, snapshot: Snapshot, insert_to_db: bool = True):
        self.snapshot = snapshot
        self.insert_to_db = insert_to_db

    async def _process(
        self,
    ) -> Union[List[Script], List[DnsRecord], List[Classification]]:
        raise NotImplementedError()

    async def process_with_error_handling(
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
        return await instance.process_with_error_handling()
