from datetime import date, datetime
from typing import Optional, Union

from fastapi import Query

from app import schemas, types


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
        from_at: Optional[Union[datetime, date]] = Query(
            None,
            title="From at",
            description="Datetime or date in ISO 8601 format",
            alias="fromAt",
        ),
        to_at: Optional[Union[datetime, date]] = Query(
            None,
            title="To at",
            description="Datetime or date in ISO 8601 format",
            alias="toAt",
        ),
        search_after: Optional[types.ULID] = Query(
            None,
            alias="searchAfter",
        ),
        search_before: Optional[types.ULID] = Query(
            None,
            alias="searchBefore",
        ),
    ):
        self.name = name
        self.target = target
        self.source = source
        self.from_at = from_at
        self.to_at = to_at
        self.search_after = search_after
        self.search_before = search_before

    def to_model(self) -> schemas.RuleSearchFilters:
        return schemas.RuleSearchFilters(
            name=self.name,
            target=self.target,
            source=self.source,
            from_at=self.from_at,
            to_at=self.to_at,
            search_after=self.search_after,
            search_before=self.search_before,
        )
