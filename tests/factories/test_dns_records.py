import pytest

from tests.utils import make_snapshot
from uzen.factories.dns_records import DnsRecordFactory


@pytest.mark.asyncio
async def test_build_from_snapshot():
    snapshot = make_snapshot()

    records = await DnsRecordFactory.from_snapshot(snapshot)
    for record in records:
        print(record.value)
    assert len(records) > 0
