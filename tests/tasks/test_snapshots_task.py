import pytest

from uzen.models.snapshots import Snapshot
from uzen.tasks.snapshots import UpdateProcessingTask


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_update_processing_task(client):
    snapshot = await Snapshot.get(id=1)
    assert snapshot.processing

    await UpdateProcessingTask.process(snapshot)

    snapshot = await Snapshot.get(id=1)
    assert not snapshot.processing
