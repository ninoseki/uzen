from typing import List

import pytest

from app import models
from app.factories.indicators import IndicatorsFactory


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts")
async def test_build_from_snapshot(snapshots: List[models.Snapshot]):
    id_ = snapshots[0].id
    snapshot = await models.Snapshot.get_by_id(id_)

    indicators = IndicatorsFactory.from_snapshot(snapshot)
    assert len(indicators.ip_addresses) == 0
    assert len(indicators.hostnames) == 1
    assert len(indicators.hashes) == 1
