from typing import List

from loguru import logger

from uzen.models.matches import Match
from uzen.models.snapshots import Snapshot
from uzen.schemas.matches import MatchResult
from uzen.services.rule_matcher import RuleMatcher
from uzen.tasks import AbstractTask


class MatchinbgTask(AbstractTask):
    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot

    async def _process(self):
        logger.debug("Start matching job...")

        snapshot_ = await Snapshot.get(id=self.snapshot.id).prefetch_related("_scripts")
        matcher = RuleMatcher(snapshot_)
        results: List[MatchResult] = await matcher.scan()

        matches = [
            Match(
                snapshot_id=self.snapshot.id,
                rule_id=result.rule_id,
                script_id=result.script_id,
                matches=[match.dict() for match in result.matches],
            )
            for result in results
        ]
        await Match.bulk_create(matches)

        logger.debug(f"Snapshot {self.snapshot.id} matches with {len(matches)} rule(s)")
        logger.debug("Matching job is finished")

    @classmethod
    async def process(cls, snapshot: Snapshot):
        instance = cls(snapshot)
        return await instance.safe_process()
