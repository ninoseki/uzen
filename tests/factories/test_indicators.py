import pytest

from app import models
from app.factories.indicators import IndicatorsFactory
from tests.helper import first_snapshot_id


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts_setup")
async def test_build_from_snapshot():
    id_ = await first_snapshot_id()
    snapshot = await models.Snapshot.get_by_id(id_)

    indicators = IndicatorsFactory.from_snapshot(snapshot)
    assert len(indicators.ip_addresses) == 0
    assert len(indicators.hostnames) == 1
    assert len(indicators.hashes) == 1
