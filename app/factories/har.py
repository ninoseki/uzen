from app import dataclasses, models


class HARFactory:
    @staticmethod
    def from_dataclass(har: dataclasses.HAR) -> models.HAR:
        return models.HAR(data=har.to_json())
