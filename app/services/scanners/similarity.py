import itertools
from functools import partial
from typing import Any, Dict, List, Optional

import aiometer
from d8s_hashes import sha256
from niteru.html_parser import parse_html
from niteru.similarity import similarity, similarity_by_tags_and_classes

from app import dataclasses, models, schemas
from app.services.scanners.constants import CHUNK_SIZE, MAX_AT_ONCE
from app.services.scanners.utils import search_snapshots


def build_similarity_result_table(
    results: List[dataclasses.SimilarityResult],
) -> Dict[str, dataclasses.SimilarityResult]:
    table: Dict[str, dataclasses.SimilarityResult] = {}
    for result in results:
        table[result.html_id] = result

    return table


class SimilarityScanner:
    def __init__(
        self,
        html: str,
        threshold: Optional[float] = None,
    ):
        self.html = html
        self.id: str = sha256(html)

        parsed = parse_html(html)
        self.tags = parsed.tags
        self.classes = parsed.classes

        if threshold is None:
            threshold = 0.9

        self.threshold: float = threshold

    async def partial_scan(self, ids: List[str]) -> List[dataclasses.SimilarityResult]:
        """Find similar HTMLs

        Arguments:
            ids {List[str]} -- A list of ids of HTMLs

        Returns:
            List[dataclasses.SimilarityResult] -- A list of similarity check results
        """

        htmls = await models.HTML.filter(id__in=ids)
        results: List[dataclasses.SimilarityResult] = []

        for html in htmls:
            tags = (self.tags, html.tags)
            classes = (self.classes, html.classes)

            similarity_: float = 0.0
            if len(tags) > 0:
                similarity_ = similarity_by_tags_and_classes(tags, classes, k=0.3)
            else:
                # fallback to support old records
                similarity_ = similarity(self.html, html.content, k=0.3)

            results.append(
                dataclasses.SimilarityResult(
                    html_id=html.id,
                    similarity=similarity_,
                    threshold=self.threshold,
                )
            )

        return results

    async def scan_snapshots(
        self,
        filters: Optional[Dict[str, Any]] = None,
        size: Optional[int] = None,
        offset: Optional[int] = None,
        exclude_hostname: Optional[str] = None,
        exclude_ip_address: Optional[str] = None,
    ) -> List[schemas.SimilarityScanResult]:
        """Find snapshots which have similar HTML

        Keyword Arguments:
            filters {dict} -- Filters for snapshot search (default: {{}})

        Returns:
            List[schemas.SimilarityScanResult] -- A list of similarity scan results
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
        flatten_results = list(itertools.chain.from_iterable(results))

        similar_results = [result for result in flatten_results if result.is_similar]
        html_ids = [result.html_id for result in similar_results]

        plain_snapshots: List[Dict[str, Any]] = await models.Snapshot.filter(
            html_id__in=html_ids
        ).values(
            *schemas.SimilarityScanResult.field_keys(),
        )

        # add similarity to plain snapshots
        table = build_similarity_result_table(similar_results)
        for snapshot in plain_snapshots:
            html_id = snapshot.get("html_id")
            if html_id is None:
                continue

            result = table.get(html_id)
            if result is None:
                continue

            snapshot["similarity"] = result.similarity

        return [
            schemas.SimilarityScanResult(**snapshot) for snapshot in plain_snapshots
        ]
