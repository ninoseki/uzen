from typing import TYPE_CHECKING, Optional

from app import schemas

if TYPE_CHECKING:
    from app.models.match import Match


def build_script(match: "Match") -> Optional[schemas.Script]:
    if match.script is not None:
        return match.script.to_model()

    return None


class MatchBuilder:
    @classmethod
    def build(cls, match: "Match") -> schemas.Match:
        return schemas.Match(
            id=match.id,
            matches=match.matches,
            created_at=match.created_at,
            snapshot=match.snapshot.to_plain_model(),
            rule=match.rule.to_model(),
            script=build_script(match),
        )
