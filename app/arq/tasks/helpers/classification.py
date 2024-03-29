from typing import List

from loguru import logger

from app import models
from app.arq.tasks.helpers.abstract import EnrichmentHelper
from app.factories.classification import ClassificationFactory


class ClassificationHelper(EnrichmentHelper):
    async def _process(self) -> List[models.Classification]:
        logger.debug(f"Fetch classifications of {self.snapshot.url}")
        classifications = await ClassificationFactory.from_snapshot(self.snapshot)

        if self.insert_to_db:
            await models.Classification.bulk_create(classifications)

        return classifications
