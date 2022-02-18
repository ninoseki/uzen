from typing import List

import pytest

from app import models
from app.arq.tasks.classes.snapshot import UpdateProcessingTask


@pytest.mark.asyncio
@pytest.mark.usefixtures("client")
async def test_update_processing_task(snapshots: List[models.Snapshot]):
    id_ = snapshots[0].id

    snapshot = await models.Snapshot.get(id=id_)
    assert snapshot.processing

    await UpdateProcessingTask.process(snapshot)

    snapshot = await models.Snapshot.get(id=id_)
    assert not snapshot.processing
