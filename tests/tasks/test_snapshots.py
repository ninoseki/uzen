import pytest

from tests.utils import first_snapshot_id
from uzen.models.snapshots import Snapshot
from uzen.tasks.snapshots import UpdateProcessingTask


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_update_processing_task(client):
    id_ = await first_snapshot_id()
    snapshot = await Snapshot.get(id=id_)
    assert snapshot.processing

    await UpdateProcessingTask.process(snapshot)

    snapshot = await Snapshot.get(id=id_)
    assert not snapshot.processing
