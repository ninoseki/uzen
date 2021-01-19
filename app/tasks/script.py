import dataclasses
from typing import List

from loguru import logger

from app import dataclasses
from app.factories.script import ScriptFactory
from app.tasks import EnrichmentTask
from app.utils.script import save_script_files


class ScriptTask(EnrichmentTask):
    async def _process(self) -> List[dataclasses.ScriptFile]:
        logger.debug(f"Fetch scripts from {self.snapshot.url}")

        script_files = await ScriptFactory.from_snapshot(self.snapshot)

        if self.insert_to_db:
            await save_script_files(script_files, self.snapshot.id)

        return script_files
