import asyncio
import itertools
from typing import List, Optional, cast

import yara

from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot
from uzen.schemas.yara import ScanResult, YaraMatch, YaraResult
from uzen.services.matches_converter import MatchesConverter
from uzen.services.searchers.snapshots import SnapshotSearcher

CHUNK_SIZE = 100
PARALLEL_LIMIT = 10
sem = asyncio.Semaphore(PARALLEL_LIMIT)


class YaraScanner:
    def __init__(self, source: str):
        self.rule: yara.Rules = yara.compile(source=source)

    async def partial_scan_for_scripts(self, ids: List[int]) -> List[YaraResult]:
        scripts = await Script.filter(snapshot_id__in=ids).values(
            "snapshot_id", "content"
        )
        matched_results = []
        for script in scripts:
            snapshot_id = script.get("snapshot_id")
            content = script.get("content")
            matches = self.match(data=content)
            if len(matches) > 0:
                result = YaraResult(
                    snapshot_id=snapshot_id,
                    script_id=script.id,
                    target="script",
                    matches=MatchesConverter.convert(matches),
                )
                matched_results.append(result)

        return matched_results

    async def partial_scan(self, target: str, ids: List[int]) -> List[YaraResult]:
        """Scan a list of snapshots with a YARA rule

        Arguments:
            target {str} -- A target of a snapshot's attribute
            ids {List[int]} -- A list of ids of snapshots

        Returns:
            List[int] -- A list of ids which are matched with a YARA rule
        """
        async with sem:
            if target == "script":
                return await self.partial_scan_for_scripts(ids)

            snapshots = await Snapshot.filter(id__in=ids).values("id", target)
            matched_results = []
            for snapshot in snapshots:
                snapshot_id = snapshot.get("id")
                data = snapshot.get(target, "")
                matches = self.match(data=data)
                if len(matches) > 0:
                    result = YaraResult(
                        snapshot_id=snapshot_id,
                        script_id=None,
                        target=target,
                        matches=matches,
                    )
                    matched_results.append(result)

            return matched_results

    async def scan_snapshots(
        self, target: str = "body", filters: dict = {}
    ) -> List[ScanResult]:
        """Scan snapshots data with a YARA rule

        Keyword Arguments:
            target {str} -- A target of a snapshot's attribute (default: {"body"})
            filters {dict} -- Filters for snapshot search (default: {{}})

        Returns:
            List[SearchResultModel] -- A list of simlified snapshot models
        """
        # get snapshots ids based on filters
        snapshot_ids: object = await SnapshotSearcher.search(filters, id_only=True)
        snapshot_ids = cast(List[int], snapshot_ids)
        if len(snapshot_ids) == 0:
            return []

        # split ids into chunks
        chunks = [
            snapshot_ids[i : i + CHUNK_SIZE]
            for i in range(0, len(snapshot_ids), CHUNK_SIZE)
        ]
        # make scan tasks
        tasks = [self.partial_scan(target=target, ids=chunk) for chunk in chunks]
        completed, pending = await asyncio.wait(tasks)
        results = list(itertools.chain(*[t.result() for t in completed]))

        matched_ids = [result.snapshot_id for result in results]
        snapshots: List[dict] = (
            await Snapshot.filter(id__in=matched_ids)
            .order_by("-id")
            .values(*ScanResult.field_keys())
        )
        for idx in range(len(results)):
            result = results[idx]
            snapshot = snapshots[idx]
            snapshot["yara_result"] = result

        return [ScanResult(**snapshot) for snapshot in snapshots]

    def match(self, data: Optional[str]) -> List[YaraMatch]:
        """Scan a data with a YARA rule

        Arguments:
            data {Optional[str]} -- Data to scan

        Returns:
            List[yara.Match] -- YARA matches
        """
        data = "" if data is None else data
        return MatchesConverter.convert(self.rule.match(data=data))
