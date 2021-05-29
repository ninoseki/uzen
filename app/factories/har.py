from playwright_har_tracer.dataclasses.har import Har

from app import models


class HarFactory:
    @staticmethod
    def from_dataclass(har: Har) -> models.HAR:
        return models.HAR(data=har.to_json())
