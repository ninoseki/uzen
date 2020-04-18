from typing import Optional
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
        from_at: Optional[str] = Query(
            None, title="From at", description="A datetime (from)"
        ),
        to_at: Optional[str] = Query(
            None, title="To at", description="A datetime (to)"
        ),
    ):
        self.rule_id = rule_id
        self.snapshot_id = snapshot_id
        self.from_at = from_at
        self.to_at = to_at
