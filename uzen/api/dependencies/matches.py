from typing import Optional

from fastapi import Query


class SearchFilters:
    def __init__(
        self,
        rule_id: Optional[int] = Query(
            None, title="Rule ID", description="An ID of the rule"
        ),
        snapshot_id: Optional[int] = Query(
            None, title="Snapshot ID", description="An ID of the snapshot"
        ),
    ):
        self.rule_id = rule_id
        self.snapshot_id = snapshot_id
