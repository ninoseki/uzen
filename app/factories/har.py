from app import dataclasses, models


class HarFactory:
    @staticmethod
    def from_dataclass(har: dataclasses.Har) -> models.HAR:
        return models.HAR(data=har.to_json())
