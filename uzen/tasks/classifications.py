from typing import List

from loguru import logger

from uzen.models.classifications import Classification
from uzen.services.classifications import ClassificationBuilder
from uzen.tasks import EnrichmentTask


class ClassificationTask(EnrichmentTask):
    async def _process(self) -> List[Classification]:
        logger.debug(f"Fetch classifications of {self.snapshot.url}")
        classifications = ClassificationBuilder.build_from_snapshot(self.snapshot)
        if self.insert_to_db:
            await Classification.bulk_create(classifications)

        return classifications
