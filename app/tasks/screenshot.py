from loguru import logger

from app.tasks import AbstractSyncTask
from app.utils.minio import upload_screenshot


class UploadScrenshotTask(AbstractSyncTask):
    def __init__(self, uuid: str, screenshot: bytes):
        self.screenshot = screenshot
        self.uuid = uuid

    def _process(self) -> None:
        upload_screenshot("uzen-screenshot", self.uuid, self.screenshot)
        logger.debug(f"Screenshot is uploadted as {self.uuid}.png")

    @classmethod
    def process(cls, uuid: str, screenshot: bytes) -> None:
        instance = cls(uuid, screenshot)
        return instance.safe_process()
