from typing import List

from loguru import logger

from app import dataclasses
from app.factories.script import ScriptFactory
from app.tasks import EnrichmentTask


class ScriptTask(EnrichmentTask):
    async def _process(self) -> List[dataclasses.ScriptFile]:
        logger.debug(f"Fetch scripts from {self.snapshot.url}")

        return await ScriptFactory.from_snapshot(self.snapshot)
