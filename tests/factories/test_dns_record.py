import pytest

from app.factories.dns_record import DnsRecordFactory
from tests.helper import make_snapshot


@pytest.mark.asyncio
async def test_build_from_snapshot():
    snapshot = make_snapshot()

    records = await DnsRecordFactory.from_snapshot(snapshot)
    assert len(records) > 0
