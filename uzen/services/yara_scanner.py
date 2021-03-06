import itertools
from functools import partial
from typing import Dict, List, Optional, cast
from uuid import UUID

import aiometer
import yara

from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot
from uzen.schemas.yara import ScanResult, YaraMatch, YaraResult
from uzen.services.matches_converter import MatchesConverter
from uzen.services.searchers.snapshots import SnapshotSearcher

CHUNK_SIZE = 100
MAX_AT_ONCE = 10


class YaraScanner:
    def __init__(self, source: str):
        self.rule: yara.Rules = yara.compile(source=source)

    async def partial_scan_for_scripts(self, ids: List[UUID]) -> List[YaraResult]:
        scripts = await Script.filter(snapshot_id__in=ids).values(
            "id", "snapshot_id", "content"
        )
        matched_results = []
        for script in scripts:
            snapshot_id = script.get("snapshot_id")
            content = script.get("content")
            matches = self.match(data=content)
            if len(matches) > 0:
                result = YaraResult(
                    snapshot_id=snapshot_id,
                    script_id=script.get("id"),
                    target="script",
                    matches=matches,
                )
                matched_results.append(result)

        return matched_results

    async def partial_scan(self, target: str, ids: List[UUID]) -> List[YaraResult]:
        """Scan a list of snapshots with a YARA rule

        Arguments:
            target {str} -- A target of a snapshot's attribute
            ids {List[int]} -- A list of ids of snapshots

        Returns:
            List[int] -- A list of ids which are matched with a YARA rule
        """
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
        self,
        target: str = "body",
        filters: dict = {},
        size: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[ScanResult]:
        """Scan snapshots data with a YARA rule

        Keyword Arguments:
            target {str} -- A target of a snapshot's attribute (default: {"body"})
            filters {dict} -- Filters for snapshot search (default: {{}})

        Returns:
            List[SearchResultModel] -- A list of simlified snapshot models
        """
        # get snapshots ids based on filters
        search_results = await SnapshotSearcher.search(
            filters, id_only=True, size=size, offset=offset
        )
        snapshot_ids = cast(List[UUID], search_results.results)
        if len(snapshot_ids) == 0:
            return []

        # split ids into chunks
        chunks = [
            snapshot_ids[i : i + CHUNK_SIZE]
            for i in range(0, len(snapshot_ids), CHUNK_SIZE)
        ]
        # make scan tasks
        tasks = [partial(self.partial_scan, target, chunk) for chunk in chunks]
        results = await aiometer.run_all(tasks, max_at_once=MAX_AT_ONCE)
        flatten_results = list(itertools.chain.from_iterable(results))

        matched_ids = [result.snapshot_id for result in flatten_results]
        snapshots: List[dict] = (
            await Snapshot.filter(id__in=matched_ids).values(*ScanResult.field_keys())
        )

        table = self._build_snapshot_table(snapshots)
        for result in flatten_results:
            snapshot = table.get(str(result.snapshot_id))
            if snapshot is not None:
                snapshot["yara_result"] = result

        return [ScanResult(**snapshot) for snapshot in snapshots]

    def _build_snapshot_table(self, snapshots: List[dict]) -> Dict[str, dict]:
        table = {}
        for snapshot in snapshots:
            id_ = str(snapshot.get("id"))
            table[id_] = snapshot
        return table

    def match(self, data: Optional[str]) -> List[YaraMatch]:
        """Scan a data with a YARA rule

        Arguments:
            data {Optional[str]} -- Data to scan

        Returns:
            List[yara.Match] -- YARA matches
        """
        data = "" if data is None else data
        return MatchesConverter.convert(self.rule.match(data=data, timeout=60))
