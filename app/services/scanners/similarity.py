import itertools
from functools import partial
from typing import Any, Dict, List, Optional

import aiometer
from niteru import similarity

from app import models, schemas
from app.services.scanners.constants import CHUNK_SIZE, MAX_AT_ONCE
from app.services.scanners.utils import search_snapshots
from app.utils.hash import calculate_sha256


def is_similar(html1: str, html2: str, threshold: float = 0.9):
    return similarity(html1, html2, k=0.3) > threshold


class SimilarityScanner:
    def __init__(
        self,
        html: str,
        threshold: Optional[float] = None,
    ):
        self.html = html
        self.id: str = calculate_sha256(html)

        if threshold is None:
            threshold = 0.9

        self.threshold: float = threshold

    async def partial_scan(self, ids: List[str]) -> List[str]:
        """Find similar HTMLs

        Arguments:
            ids {List[str]} -- A list of ids of HTMLs

        Returns:
            List[models.HTML] -- A list of
        """

        htmls = await models.HTML.filter(id__in=ids)
        similar_html_ids: List[str] = []

        for html in htmls:
            if is_similar(html.content, self.html, threshold=self.threshold):
                similar_html_ids.append(html.id)

        return similar_html_ids

    async def scan_snapshots(
        self,
        filters: Optional[Dict[str, Any]] = None,
        size: Optional[int] = None,
        offset: Optional[int] = None,
        exclude_hostname: Optional[str] = None,
        exclude_ip_address: Optional[str] = None,
    ) -> List[schemas.PlainSnapshot]:
        """Find snapshots which have similar HTML

        Keyword Arguments:
            filters {dict} -- Filters for snapshot search (default: {{}})

        Returns:
            List[schemas.PlainSnapshot] -- A list of simplified snapshot models
        """
        if filters is None:
            filters = {}

        # get snapshots IDs based on filters
        search_results = await search_snapshots(
            html_id=self.id,
            exclude_hostname=exclude_hostname,
            exclude_ip_address=exclude_ip_address,
            filters=filters,
            size=size,
            offset=offset,
        )

        # convert snapshots into HTML IDs
        html_ids: List[str] = [snapshot.html_id for snapshot in search_results.results]
        html_ids = list(set(html_ids))
        if len(html_ids) == 0:
            return []

        # split IDs into chunks
        chunks = [
            html_ids[i : i + CHUNK_SIZE] for i in range(0, len(html_ids), CHUNK_SIZE)
        ]
        # make scan tasks
        tasks = [partial(self.partial_scan, chunk) for chunk in chunks]
        results = await aiometer.run_all(tasks, max_at_once=MAX_AT_ONCE)
        similar_html_ids = list(itertools.chain.from_iterable(results))

        plain_snapshots: List[Dict[str, Any]] = await models.Snapshot.filter(
            html_id__in=similar_html_ids
        ).values(
            *schemas.PlainSnapshot.field_keys(),
        )

        return [schemas.PlainSnapshot(**snapshot) for snapshot in plain_snapshots]
