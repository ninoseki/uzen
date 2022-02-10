from datetime import date, datetime
from typing import Optional, Union

from fastapi import Query

from app import schemas, types


class SearchFilters:
    def __init__(
        self,
        rule_id: Optional[types.ULID] = Query(
            None, title="Rule ID", description="An ID of the rule"
        ),
        ruleId: Optional[types.ULID] = Query(None, description="Alias of rule_id"),
        snapshot_id: Optional[types.ULID] = Query(
            None, title="Snapshot ID", description="An ID of the snapshot"
        ),
        snapshotId: Optional[types.ULID] = Query(
            None, description="Alias of snapshot_id"
        ),
        from_at: Optional[Union[datetime, date]] = Query(
            None, title="From at", description="Datetime or date in ISO 8601 format"
        ),
        fromAt: Optional[Union[datetime, date]] = Query(
            None, description="Alias of from_at"
        ),
        to_at: Optional[Union[datetime, date]] = Query(
            None, title="To at", description="Datetime or date in ISO 8601 format"
        ),
        toAt: Optional[Union[datetime, date]] = Query(
            None, description="Alias of to_at"
        ),
    ):
        self.rule_id = rule_id or ruleId
        self.snapshot_id = snapshot_id or snapshotId
        self.from_at = from_at or fromAt
        self.to_at = to_at or toAt

    def to_model(self) -> schemas.MatchSearchFilters:
        return schemas.MatchSearchFilters(
            rule_id=self.rule_id,
            snapshot_id=self.snapshot_id,
            from_at=self.from_at,
            to_at=self.to_at,
        )
