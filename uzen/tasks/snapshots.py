from uzen.models.snapshots import Snapshot
from uzen.tasks import AbstractTask


class UpdateProcessingTask(AbstractTask):
    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot

    async def _process(self):
        self.snapshot.processing = False
        await self.snapshot.save()

    @classmethod
    async def process(cls, snapshot: Snapshot):
        instance = cls(snapshot)
        return await instance.safe_process()
