from typing import List

from loguru import logger

from app.factories.scripts import ScriptFactory
from app.models.scripts import Script
from app.tasks import EnrichmentTask


class ScriptTask(EnrichmentTask):
    async def _process(self) -> List[Script]:
        logger.debug(f"Fetch scripts from {self.snapshot.url}")
        scripts = await ScriptFactory.from_snapshot(self.snapshot)
        if self.insert_to_db:
            await Script.bulk_create(scripts)

        return scripts
