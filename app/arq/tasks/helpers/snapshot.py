from app import models
from app.arq.tasks.helpers.abstract import AbstractAsyncHelper


class UpdateProcessingHelper(AbstractAsyncHelper):
    def __init__(self, snapshot: models.Snapshot):
        self.snapshot = snapshot

    async def _process(self) -> None:
        self.snapshot.processing = False
        await self.snapshot.save()

    @classmethod
    async def process(cls, snapshot: models.Snapshot) -> None:
        instance = cls(snapshot)
        return await instance.process_with_error_handling()
