from typing import List

from tortoise.query_utils import Q

from uzen.models.dns_records import DnsRecord


class DnsRecordSearcher:
    @staticmethod
    async def search(filters: dict) -> List[DnsRecord]:
        """Search DNS records
        
        Arguments:
            filters {dict} -- Filters for DNS record search
        
        Returns:
            List[DnsRecord] -- a list of matched DNS records
        """
        queries = []

        snapshot_id = filters.get("snapshot_id")
        if snapshot_id is not None:
            queries.append(Q(snapshot_id=snapshot_id))

        value = filters.get("value")
        if value is not None:
            queries.append(Q(value=value))

        query = Q(*queries)

        return await DnsRecord.filter(query).order_by("type")
