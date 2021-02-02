import pytest

from app.models.snapshot import Snapshot
from app.tasks.snapshot import UpdateProcessingTask
from tests.helper import first_snapshot_id


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_update_processing_task(client):
    id_ = await first_snapshot_id()
    snapshot = await Snapshot.get(id=id_)
    assert snapshot.processing

    await UpdateProcessingTask.process(snapshot)

    snapshot = await Snapshot.get(id=id_)
    assert not snapshot.processing