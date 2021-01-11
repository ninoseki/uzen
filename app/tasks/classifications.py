from typing import List

from loguru import logger

from app.factories.classifications import ClassificationFactory
from app.models.classifications import Classification
from app.tasks import EnrichmentTask


class ClassificationTask(EnrichmentTask):
    async def _process(self) -> List[Classification]:
        logger.debug(f"Fetch classifications of {self.snapshot.url}")
        classifications = ClassificationFactory.from_snapshot(self.snapshot)
        if self.insert_to_db:
            await Classification.bulk_create(classifications)

        return classifications
