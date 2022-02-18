from abc import ABC, abstractstaticmethod

from app import dataclasses


class AbstractBrowser(ABC):
    @staticmethod
    @abstractstaticmethod
    async def take_snapshot(
        url: str,
        options: dataclasses.BrowserOptions,
    ) -> dataclasses.SnapshotModelWrapper:
        raise NotImplementedError()
