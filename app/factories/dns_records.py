from functools import partial
from typing import List

import aiometer
from dns.asyncresolver import Resolver
from dns.exception import DNSException

from app.models.dns_records import DnsRecord
from app.models.snapshots import Snapshot
from app.schemas.dns_records import BaseDnsRecord

TYPES: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"]


async def resolve(
    resolver: Resolver,
    hostname: str,
    rdtype="A",
    rdclass="IN",
    tcp=False,
    source=None,
    raise_on_no_answer=True,
    source_port=0,
    lifetime=None,
) -> List[BaseDnsRecord]:
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
        return [BaseDnsRecord(type=rdtype, value=str(rr)) for rr in answer]
    except DNSException:
        return []


async def query(hostname: str) -> List[BaseDnsRecord]:
    """Quqery DNS records

    Arguments:
        hostname {str} -- A hostname to query

    Returns:
        List[BaseDnsRecord] -- A list of DNS records
    """
    resolver = Resolver()
    tasks = [partial(resolve, resolver, hostname, record_type) for record_type in TYPES]
    results = await aiometer.run_all(tasks)
    return sum(results, [])


class DnsRecordFactory:
    @staticmethod
    async def from_snapshot(snapshot: Snapshot) -> List[DnsRecord]:
        return [
            DnsRecord(
                type=record.type,
                value=record.value,
                # insert a dummy ID if a snapshot doesn't have ID
                snapshot_id=snapshot.id or -1,
            )
            for record in await query(snapshot.hostname)
        ]

    @staticmethod
    async def from_hostname(hostname: str) -> List[BaseDnsRecord]:
        return await query(hostname)
