import asyncio
from typing import List, Optional

import yara

from uzen.models.snapshots import Snapshot
from uzen.models.scripts import Script
from uzen.services.snapshot_search import SnapshotSearcher

CHUNK_SIZE = 100
PARALLEL_LIMIT = 10
sem = asyncio.Semaphore(PARALLEL_LIMIT)


class YaraScanner:
    def __init__(self, source: str):
        self.rule: yara.Rules = yara.compile(source=source)

    async def partial_scan_for_scripts(self, ids: List[int]) -> List[int]:
        scripts = await Script.filter(snapshot_id__in=ids).values(
            "snapshot_id", "content"
        )
        matched_ids = []
        for script in scripts:
            snapshot_id = script.get("snapshot_id")
            content = script.get("content")
            matches = self.match(data=content)
            if len(matches) > 0:
                matched_ids.append(snapshot_id)

        return list(set(matched_ids))

    async def partial_scan(self, target: str, ids: List[int]) -> List[int]:
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
            matched_ids = []
            for snapshot in snapshots:
                id = snapshot.get("id")
                data = snapshot.get(target, "")
                matches = self.match(data=data)
                if len(matches) > 0:
                    matched_ids.append(id)

            return matched_ids

    async def scan_snapshots(
        self, target: str = "body", filters: dict = {}
    ) -> List[Snapshot]:
        """Scan snapshots data with a YARA rule

        Keyword Arguments:
            target {str} -- A target of a snapshot's attribute (default: {"body"})
            filters {dict} -- Filters for snapshot search (default: {{}})

        Returns:
            List[Snapshot] -- A list of snapshot ORM instances
        """
        # get snapshots ids based on filters
        snapshot_ids = await SnapshotSearcher.search(filters, id_only=True)
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
        results = [t.result() for t in completed]

        matched_ids = sum(results, [])
        return await Snapshot.filter(id__in=matched_ids).order_by("-id")

    def match(self, data: Optional[str]) -> List[yara.Match]:
        """Scan a data with a YARA rule

        Arguments:
            data {Optional[str]} -- Data to scan

        Returns:
            List[yara.Match] -- YARA matches
        """
        data = "" if data is None else data
        return self.rule.match(data=data)
