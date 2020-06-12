import base64
import os
import zlib
from typing import Union
from uuid import UUID

from tortoise import fields

from uzen.models.base import AbstractBaseModel
from uzen.schemas.screenshots import BaseScreenshot
from uzen.schemas.screenshots import Screenshot as ScreenshotModel


def not_found_png() -> bytes:
    current_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(current_path, "../../frontend/dist/images/not-found.png")
    with open(path, "rb") as f:
        return f.read()


class Screenshot(AbstractBaseModel):
    _data: str = fields.TextField(source_field="data")

    snapshot: fields.OneToOneRelation["Snapshot"] = fields.OneToOneField(
        "models.Snapshot", related_name="_screenshot", on_delete=fields.CASCADE
    )

    @property
    def data(self) -> str:
        try:
            b64decoded = base64.b64decode(self._data.encode())
            decompressed = zlib.decompress(b64decoded)
            return decompressed.decode()
        except zlib.error:
            return self._data

    @data.setter
    def data(self, data: str):
        compressed = zlib.compress(data.encode())
        self._data = base64.b64encode(compressed).decode()

    @property
    def png(self) -> bytes:
        if self.data != "":
            return base64.b64decode(self.data)
        return not_found_png()

    @classmethod
    async def get_by_snapshot_id(cls, id_: UUID) -> "Screenshot":
        return await cls.get(snapshot_id=id_)

    def to_model(self) -> Union[ScreenshotModel, BaseScreenshot]:
        if self.snapshot_id is not None:
            return ScreenshotModel.from_orm(self)

        return BaseScreenshot.from_orm(self)

    class Meta:
        table = "screenshots"
