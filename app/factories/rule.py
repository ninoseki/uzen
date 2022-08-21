from typing import TYPE_CHECKING

from app import schemas

if TYPE_CHECKING:
    from app.models.rule import Rule


def build_snapshots(rule: "Rule"):
    if hasattr(rule, "related_snapshots"):
        snapshots = rule.related_snapshots or []
        return [snapshot.to_model() for snapshot in snapshots]

    return []


class RuleFactory:
    @staticmethod
    def from_model(rule: "Rule") -> schemas.Rule:
        return schemas.Rule(
            id=rule.id,
            name=rule.name,
            source=rule.source,
            target=rule.target,
            allowed_network_addresses=rule.allowed_network_addresses,
            disallowed_network_addresses=rule.disallowed_network_addresses,
            allowed_resource_hashes=rule.allowed_resource_hashes,
            disallowed_resource_hashes=rule.disallowed_resource_hashes,
            created_at=rule.created_at,
            updated_at=rule.updated_at,
            snapshots=build_snapshots(rule),
        )
