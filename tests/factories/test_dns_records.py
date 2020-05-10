from tests.utils import make_snapshot
from uzen.factories.dns_records import DnsRecordFactory


def test_build_from_snapshot():
    snapshot = make_snapshot()

    records = DnsRecordFactory.from_snapshot(snapshot)
    assert len(records) > 0
