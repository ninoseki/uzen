from typing import Any, Dict, List, Optional, cast
from uuid import UUID

from tortoise.query_utils import Q

from app import models, schemas
from app.services.searchers import AbstractSearcher
from app.services.searchers.utils import convert_to_datetime


class SnapshotSearcher(AbstractSearcher):
    @classmethod
    async def search(
        cls,
        filters: Dict[str, Any],
        size: Optional[int] = None,
        offset: Optional[int] = None,
        id_only: bool = False,
        additional_queries: Optional[List[Q]] = None,
    ) -> schemas.SnapshotsSearchResults:
        """Search snapshots

        Arguments:
            filters {dict} -- Filters for snapshot search

        Keyword Arguments:
            size {[int]} -- Number of results returned (default: {None})
            offset {[int]} -- Offset of the first result for pagination (default: {None})
            id_only {bool} -- Whether to return only a list of ids (default: {False})

        Returns:
           SearchResults -- A list of simplified snapshots and total count
        """
        queries = []

        url = filters.get("url")
        if url is not None:
            queries.append(Q(url=url))

        status = filters.get("status")
        if status is not None:
            queries.append(Q(status=status))

        hostname = filters.get("hostname")
        if hostname is not None:
            queries.append(Q(hostname=hostname))

        ip_address = filters.get("ip_address")
        if ip_address is not None:
            queries.append(Q(ip_address=ip_address))

        asn = filters.get("asn")
        if asn is not None:
            queries.append(Q(asn=asn))

        hash = filters.get("hash")
        if hash is not None:
            queries.append(
                Q(html__id=hash)
                | Q(_scripts__file_id=hash)
                | Q(_stylesheets__file_id=hash)
            )

        certificate_fingerprint = filters.get("certificate_fingerprint")
        if certificate_fingerprint is not None:
            queries.append(Q(certificate__id=certificate_fingerprint))

        from_at = filters.get("from_at")
        if from_at is not None:
            queries.append(Q(created_at__gt=convert_to_datetime(from_at)))

        to_at = filters.get("to_at")
        if to_at is not None:
            queries.append(Q(created_at__lt=convert_to_datetime(to_at)))

        if additional_queries is not None:
            queries.extend(additional_queries)

        query = Q(*queries)

        # Run search
        instance = cls(
            model=models.Snapshot,
            query=query,
            values=schemas.PlainSnapshot.field_keys(),
        )

        results = await instance._search(size=size, offset=offset, id_only=id_only)

        if id_only:
            return schemas.SnapshotsSearchResults(
                results=cast(List[UUID], results.results), total=results.total
            )

        results_ = cast(List[Dict[str, Any]], results.results)
        return schemas.SnapshotsSearchResults(
            results=[schemas.PlainSnapshot(**result) for result in results_],
            total=results.total,
        )
