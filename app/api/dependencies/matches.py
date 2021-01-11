from datetime import date, datetime
from typing import Optional, Union
from uuid import UUID

from fastapi import Query


class SearchFilters:
    def __init__(
        self,
        rule_id: Optional[UUID] = Query(
            None, title="Rule ID", description="An ID of the rule"
        ),
        ruleId: Optional[UUID] = Query(None, description="Alias of rule_id"),
        snapshot_id: Optional[UUID] = Query(
            None, title="Snapshot ID", description="An ID of the snapshot"
        ),
        snapshotId: Optional[UUID] = Query(None, description="Alias of snapshot_id"),
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
