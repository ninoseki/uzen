from typing import List

from loguru import logger

from app import models, schemas
from app.services.rule_matcher import RuleMatcher
from app.tasks import AbstractAsyncTask


class MatchinbgTask(AbstractAsyncTask):
    def __init__(self, snapshot: models.Snapshot):
        self.snapshot = snapshot

    async def _process(self):
        logger.debug("Start matching job...")

        snapshot_ = await models.Snapshot.get(id=self.snapshot.id).prefetch_related(
            "_scripts__file", "whois", "certificate", "html"
        )

        matcher = RuleMatcher(snapshot_)
        results: List[schemas.MatchResult] = await matcher.scan()

        matches = [
            models.Match(
                snapshot_id=self.snapshot.id,
                rule_id=result.rule_id,
                script_id=result.script_id,
                matches=[match.dict() for match in result.matches],
            )
            for result in results
        ]
        await models.Match.bulk_create(matches)

        logger.debug(f"Snapshot {self.snapshot.id} matches with {len(matches)} rule(s)")
        logger.debug("Matching job is finished")

    @classmethod
    async def process(cls, snapshot: models.Snapshot):
        instance = cls(snapshot)
        return await instance.safe_process()
