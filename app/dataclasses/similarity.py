from dataclasses import dataclass


@dataclass
class SimilarityResult:
    html_id: str
    similarity: float
    threshold: float

    @property
    def is_similar(self) -> bool:
        return self.similarity > self.threshold
