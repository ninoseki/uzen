from typing import List

from loguru import logger

from app import dataclasses, models
from app.arq.tasks import AbstractAsyncTask
from app.factories.script import ScriptFactory


class ScriptTask(AbstractAsyncTask):
    def __init__(self, snapshot: models.Snapshot):
        self.snapshot = snapshot

    async def _process(self) -> List[dataclasses.ScriptFile]:
        logger.debug(f"Fetch scripts from {self.snapshot.url}")

        return await ScriptFactory.from_snapshot(self.snapshot)

    @classmethod
    async def process(cls, snapshot: models.Snapshot) -> List[dataclasses.ScriptFile]:
        instance = cls(snapshot)
        return await instance.safe_process()
