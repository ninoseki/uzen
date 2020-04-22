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
        snapshot_id: Optional[UUID] = Query(
            None, title="Snapshot ID", description="An ID of the snapshot"
        ),
        from_at: Optional[Union[datetime, date]] = Query(
            None, title="From at", description="Datetime or date in ISO 8601 format"
        ),
        to_at: Optional[Union[datetime, date]] = Query(
            None, title="To at", description="Datetime or date in ISO 8601 format"
        ),
    ):
        self.rule_id = rule_id
        self.snapshot_id = snapshot_id
        self.from_at = from_at
        self.to_at = to_at
