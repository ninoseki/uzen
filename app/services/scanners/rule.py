import itertools
from functools import partial
from typing import Any, List, cast

import aiometer

from app import models, schemas, types
from app.services.searchers.rule import RuleSearcher
from app.utils.chunk import chunknize

from .constants import CHUNK_SIZE, MAX_AT_ONCE
from .yara import YaraScanner


def has_intersection(list1: List[Any], list2: List[Any]) -> bool:
    intersection = set(list1).intersection(list2)
    return len(intersection) > 0


def is_snapshot_allowed_by_rule(snapshot: models.Snapshot, rule: models.Rule) -> bool:
    if rule.allowed_network_addresses is not None:
        values = rule.allowed_network_addresses.split(",")
        network_values = [
            str(snapshot.ip_address),
            str(snapshot.asn),
            str(snapshot.hostname),
        ]
        return has_intersection(values, network_values)

    if rule.allowed_resource_hashes is not None:
        values = rule.allowed_resource_hashes.split(",")

        scripts = [str(script.file.id) for script in snapshot._scripts]
        stylesheets = [str(stylesheet.file.id) for stylesheet in snapshot._stylesheets]
        hashes = scripts + stylesheets

        return has_intersection(values, hashes)

    return True


def is_snapshot_disallowed_by_rule(
    snapshot: models.Snapshot, rule: models.Rule
) -> bool:
    if rule.disallowed_network_addresses is not None:
        values = rule.disallowed_network_addresses.split(",")
        network_values = [
            str(snapshot.ip_address),
            str(snapshot.asn),
            str(snapshot.hostname),
        ]
        return has_intersection(values, network_values)

    if rule.disallowed_resource_hashes is not None:
        values = rule.disallowed_resource_hashes.split(",")

        scripts = [str(script.file.id) for script in snapshot._scripts]
        stylesheets = [str(stylesheet.file.id) for stylesheet in snapshot._stylesheets]
        hashes = scripts + stylesheets

        return has_intersection(values, hashes)

    return False


class RuleScanner:
    def __init__(self, snapshot: models.Snapshot):
        self.snapshot = snapshot

    def _extract_data_from_snapshot(self, target: str = "html") -> str:
        if target == "html":
            return str(self.snapshot.html.content)

        if target == "whois":
            return str(self.snapshot.whois.content)

        if target == "certificate":
            return str(self.snapshot.certificate.content)

        return ""

    def _partial_scan_for_script(
        self, rule: models.Rule, scanner: YaraScanner
    ) -> List[schemas.MatchResult]:
        results = []
        for script in cast(List[models.Script], self.snapshot._scripts):
            data = script.file.content
            matches = scanner.match(data)
            if len(matches) > 0:
                results.append(
                    schemas.MatchResult(
                        rule_id=rule.id, script_id=script.id, matches=matches
                    )
                )
        return results

    async def partial_scan(self, ids: List[types.ULID]) -> List[schemas.MatchResult]:
        rules: List[models.Rule] = await models.Rule.filter(id__in=ids)

        results: List[schemas.MatchResult] = []
        for rule in rules:
            # check pre-conditions
            if not is_snapshot_allowed_by_rule(self.snapshot, rule):
                continue

            if is_snapshot_disallowed_by_rule(self.snapshot, rule):
                continue

            # check with YARA
            scanner = YaraScanner(rule.source)

            if rule.target == "script":
                results.extend(
                    self._partial_scan_for_script(scanner=scanner, rule=rule)
                )
                continue

            data = self._extract_data_from_snapshot(rule.target)
            matches = scanner.match(data)
            if len(matches) > 0:
                results.append(schemas.MatchResult(rule_id=rule.id, matches=matches))

        return results

    async def scan(self) -> List[schemas.MatchResult]:
        search_results = await RuleSearcher.search_for_ids()
        rule_ids = search_results.results
        if len(rule_ids) == 0:
            return []

        # split ids into chunks
        chunks = chunknize(rule_ids, chunk_size=CHUNK_SIZE)

        # make scan tasks
        tasks = [partial(self.partial_scan, chunk) for chunk in chunks]
        results = await aiometer.run_all(tasks, max_at_once=MAX_AT_ONCE)
        flatten_results = list(itertools.chain.from_iterable(results))
        return flatten_results
