from tests.utils import make_snapshot
from uzen.services.dns_records import DnsRecordBuilder


def test_build_from_snapshot():
    snapshot = make_snapshot()

    records = DnsRecordBuilder.build_from_snapshot(snapshot)
    assert len(records) > 0
