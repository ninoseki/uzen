from typing import Optional

from fastapi import Query

from app import schemas


class SearchFilters:
    def __init__(
        self,
        name: Optional[str] = Query(
            None, title="Name", description="A name of the rule"
        ),
        target: Optional[str] = Query(
            None,
            title="Target",
            description="A target of the rule (body, certificate, script or whois)",
        ),
        source: Optional[str] = Query(
            None, title="Source", description="A source of the rule"
        ),
    ):
        self.name = name
        self.target = target
        self.source = source

    def to_model(self) -> schemas.RuleSearchFilters:
        return schemas.RuleSearchFilters(
            name=self.name, target=self.target, source=self.source
        )
