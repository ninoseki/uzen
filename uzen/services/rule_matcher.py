from typing import List, cast
import asyncio
import itertools

from uzen.models.rules import Rule
from uzen.schemas.matches import MatchResult
from uzen.models.snapshots import Snapshot
from uzen.services.searchers.rules import RuleSearcher
from uzen.services.yara_scanner import YaraScanner

CHUNK_SIZE = 100
PARALLEL_LIMIT = 10
sem = asyncio.Semaphore(PARALLEL_LIMIT)


class RuleMatcher:
    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot

    async def partial_scan(self, ids: List[int]) -> List[MatchResult]:
        async with sem:
            results: List[MatchResult] = []
            rules: List[Rule] = await Rule.filter(id__in=ids)
            for rule in rules:
                scanner = YaraScanner(rule.source)

                data = self.snapshot.to_dict().get(rule.target, "")
                matches = scanner.match(data)
                if len(matches) > 0:
                    results.append(MatchResult(rule_id=rule.id, matches=matches))

            return results

    async def scan(self) -> List[MatchResult]:
        rule_ids = cast(List[int], await RuleSearcher.search({}, id_only=True))
        if len(rule_ids) == 0:
            return []

        # split ids into chunks
        chunks = [
            rule_ids[i : i + CHUNK_SIZE] for i in range(0, len(rule_ids), CHUNK_SIZE)
        ]
        # make scan tasks
        tasks = [self.partial_scan(ids=chunk) for chunk in chunks]
        completed, pending = await asyncio.wait(tasks)
        results = list(itertools.chain(*[t.result() for t in completed]))
        return results
