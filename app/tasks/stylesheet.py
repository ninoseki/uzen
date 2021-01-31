from typing import List

from loguru import logger

from app import dataclasses, models
from app.factories.stylesheet import StylesheetFactory
from app.tasks import AbstractAsyncTask


class StylesheetTask(AbstractAsyncTask):
    def __init__(self, snapshot: models.Snapshot):
        self.snapshot = snapshot

    async def _process(self) -> List[dataclasses.StylesheetFile]:
        logger.debug(f"Fetch stylesheets from {self.snapshot.url}")

        return await StylesheetFactory.from_snapshot(self.snapshot)

    @classmethod
    async def process(
        cls, snapshot: models.Snapshot
    ) -> List[dataclasses.StylesheetFile]:
        instance = cls(snapshot)
        return await instance.safe_process()
