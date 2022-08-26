from loguru import logger

from app.arq.tasks.helpers.abstract import AbstractAsyncHelper
from app.utils.minio import upload_screenshot


class UploadScreenshotHelper(AbstractAsyncHelper):
    def __init__(self, uuid: str, screenshot: bytes):
        self.screenshot = screenshot
        self.uuid = uuid

    def _process(self) -> None:
        upload_screenshot("uzen-screenshot", self.uuid, self.screenshot)
        logger.debug(f"Screenshot is uploaded as {self.uuid}.png")

    @classmethod
    async def process(cls, uuid: str, screenshot: bytes) -> None:
        instance = cls(uuid, screenshot)
        return await instance.process_with_error_handling()
