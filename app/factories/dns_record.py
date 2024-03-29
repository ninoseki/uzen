from functools import partial
from typing import List, Optional

import aiometer
from dns.asyncresolver import Resolver
from dns.exception import DNSException

from app import models, schemas

TYPES: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"]


async def resolve(
    resolver: Resolver,
    hostname: str,
    rdtype: str = "A",
    rdclass: str = "IN",
    tcp: bool = False,
    source: Optional[str] = None,
    raise_on_no_answer: bool = True,
    source_port: int = 0,
    lifetime: Optional[float] = None,
) -> List[schemas.BaseDNSRecord]:
    try:
        answer = await resolver.resolve(
            hostname,
            rdtype,
            rdclass,
            tcp,
            source,
            raise_on_no_answer,
            source_port,
            lifetime,
            True,
        )
        return [schemas.BaseDNSRecord(type=rdtype, value=str(rr)) for rr in answer]
    except DNSException:
        return []


async def query(hostname: str) -> List[schemas.BaseDNSRecord]:
    """Query DNS records

    Arguments:
        hostname {str} -- A hostname to query

    Returns:
        List[schemas.dns_records.BaseDNSRecord] -- A list of DNS records
    """
    resolver = Resolver()
    tasks = [partial(resolve, resolver, hostname, record_type) for record_type in TYPES]
    results = await aiometer.run_all(tasks)
    return sum(results, [])


class DNSRecordFactory:
    @staticmethod
    async def from_snapshot(
        snapshot: models.Snapshot,
    ) -> List[models.DNSRecord]:
        return [
            models.DNSRecord(
                type=record.type,
                value=record.value,
                # insert a dummy ID if a snapshot doesn't have ID
                snapshot_id=snapshot.id or -1,
            )
            for record in await query(snapshot.hostname)
        ]

    @staticmethod
    async def from_hostname(hostname: str) -> List[schemas.BaseDNSRecord]:
        return await query(hostname)
