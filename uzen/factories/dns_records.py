from typing import List

import dns.resolver
from dns.exception import DNSException

from uzen.models.dns_records import DnsRecord
from uzen.models.snapshots import Snapshot
from uzen.schemas.dns_records import BaseDnsRecord

TYPES: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"]


def query(hostname: str) -> List[BaseDnsRecord]:
    """Quqery DNS records

    Arguments:
        hostname {str} -- A hostname to query

    Returns:
        List[BaseDnsRecord] -- A list of DNS records
    """
    resolver = dns.resolver.Resolver()
    records = []
    for record_type in TYPES:
        try:
            answer = resolver.query(hostname, record_type)
            for rr in answer:
                record = BaseDnsRecord(type=record_type, value=str(rr))
                records.append(record)
        except DNSException:
            pass
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
