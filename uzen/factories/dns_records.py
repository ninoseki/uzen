from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache, partial
from typing import List

from dns.exception import DNSException
from dns.resolver import Resolver

from uzen.models.dns_records import DnsRecord
from uzen.models.snapshots import Snapshot
from uzen.schemas.dns_records import BaseDnsRecord

TYPES: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"]


def _query(resolver: Resolver, hostname: str, record_type: str) -> List[BaseDnsRecord]:
    try:
        answer = resolver.query(hostname, record_type)
        return [BaseDnsRecord(type=record_type, value=str(rr)) for rr in answer]
    except DNSException:
        return []


@lru_cache()
def query(hostname: str) -> List[BaseDnsRecord]:
    """Quqery DNS records

    Arguments:
        hostname {str} -- A hostname to query

    Returns:
        List[BaseDnsRecord] -- A list of DNS records
    """
    resolver = Resolver()
    with ProcessPoolExecutor() as executor:
        futures = [
            executor.submit(partial(_query, resolver, hostname, record_type))
            for record_type in TYPES
        ]

    records = []
    for future in futures:
        records.extend(future.result())
    return records


class DnsRecordFactory:
    @staticmethod
    def from_snapshot(snapshot: Snapshot) -> List[DnsRecord]:
        return [
            DnsRecord(
                type=record.type,
                value=record.value,
                # insert a dummy ID if a snapshot doesn't have ID
                snapshot_id=snapshot.id or -1,
            )
            for record in query(snapshot.hostname)
        ]

    @staticmethod
    def from_hostname(hostname: str) -> List[BaseDnsRecord]:
        return query(hostname)
