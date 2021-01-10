import itertools
from functools import partial
from typing import List, cast
from uuid import UUID

import aiometer

from uzen.models.rules import Rule
from uzen.models.snapshots import Snapshot
from uzen.schemas.matches import MatchResult
from uzen.schemas.scripts import Script
from uzen.services.searchers.rules import RuleSearcher
from uzen.services.yara_scanner import YaraScanner

CHUNK_SIZE = 100
MAX_AT_ONCE = 10


class RuleMatcher:
    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot

    def _extract_data_from_snapshot(self, target: str = "body") -> str:
        if target == "body":
            return self.snapshot.body

        if target == "whois":
            return self.snapshot.whois

        if target == "certificate":
            return self.snapshot.certificate

        return ""

    def _partial_scan_for_script(
        self, rule: Rule, scanner: YaraScanner
    ) -> List[MatchResult]:
        results = []
        for script in cast(List[Script], self.snapshot.scripts):
            data = script.file.content
            matches = scanner.match(data)
            if len(matches) > 0:
                results.append(
                    MatchResult(rule_id=rule.id, script_id=script.id, matches=matches)
                )
        return results

    async def partial_scan(self, ids: List[UUID]) -> List[MatchResult]:
        results: List[MatchResult] = []
        rules: List[Rule] = await Rule.filter(id__in=ids)
        for rule in rules:
            scanner = YaraScanner(rule.source)

            if rule.target == "script":
                results.extend(
                    self._partial_scan_for_script(scanner=scanner, rule=rule)
                )
            else:
                data = self._extract_data_from_snapshot(rule.target)
                matches = scanner.match(data)
                if len(matches) > 0:
                    results.append(MatchResult(rule_id=rule.id, matches=matches))

        return results

    async def scan(self) -> List[MatchResult]:
        search_results = await RuleSearcher.search({}, id_only=True)
        rule_ids = cast(List[UUID], search_results.results)
        if len(rule_ids) == 0:
            return []

        # split ids into chunks
        chunks = [
            rule_ids[i : i + CHUNK_SIZE] for i in range(0, len(rule_ids), CHUNK_SIZE)
        ]
        # make scan tasks
        tasks = [partial(self.partial_scan, chunk) for chunk in chunks]
        results = await aiometer.run_all(tasks, max_at_once=MAX_AT_ONCE)
        flatten_results = list(itertools.chain.from_iterable(results))
        return flatten_results
