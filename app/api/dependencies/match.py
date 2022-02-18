from datetime import date, datetime
from typing import Optional, Union

from fastapi import Query

from app import schemas, types


class SearchFilters:
    def __init__(
        self,
        rule_id: Optional[types.ULID] = Query(
            None, title="Rule ID", description="An ID of the rule", alias="ruleId"
        ),
        snapshot_id: Optional[types.ULID] = Query(
            None,
            title="Snapshot ID",
            description="An ID of the snapshot",
            alias="snapshotId",
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
        self.rule_id = rule_id
        self.snapshot_id = snapshot_id
        self.from_at = from_at
        self.to_at = to_at
        self.search_after = search_after
        self.search_before = search_before

    def to_model(self) -> schemas.MatchSearchFilters:
        return schemas.MatchSearchFilters(
            rule_id=self.rule_id,
            snapshot_id=self.snapshot_id,
            from_at=self.from_at,
            to_at=self.to_at,
            search_after=self.search_after,
            search_before=self.search_before,
        )
