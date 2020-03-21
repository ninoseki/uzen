import pydig
from typing import List

from uzen.models.dns_records import DnsRecord
from uzen.models.schemas.dns_records import BaseDnsRecord
from uzen.models.snapshots import Snapshot

TYPES: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"]


def query(hostname: str) -> List[BaseDnsRecord]:
    records = []
    for record_type in TYPES:
        values = pydig.query(hostname, record_type)
        for value in values:
            record = BaseDnsRecord(type=record_type, value=value)
            records.append(record)
    return records


class DnsRecordBuilder:
    @staticmethod
    def build_from_snapshot(snapshot: Snapshot) -> List[DnsRecord]:
        records = query(snapshot.hostname)
        dns_records = []
        for record in records:
            dns_record = DnsRecord(
                type=record.type,
                value=record.value,
                # insert a dummy ID if a snapshot doesn't have ID
                snapshot_id=snapshot.id or -1,
            )
            dns_records.append(dns_record)
        return dns_records
