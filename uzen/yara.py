import yara

from uzen.models import Snapshot


def convert_nested_tuples(self, nested_tuples) -> list:
    array = []
    for tuples in nested_tuples:
        array.append([t.decode("utf-8") if type(t) == bytes else t for t in tuples])
    return array


def convert_yara_matches(self, matches) -> list:
    array = []
    for match in matches:
        array.append(
            dict(
                rule=match.rule,
                tags=match.tags,
                strings=self.convert_nested_tuples(match.strings),
            )
        )
    return array


class Yara:
    def __init__(self, source: str):
        self.rule = yara.compile(source=source)

    def scan(self, data: str):
        return self.rule.match(data=data)

    async def scan_all(self):
        snapshots = await Snapshot.all()
        matched_snapshots = []
        for snapshot in snapshots:
            matches = self.scan(snapshot.body)
            if len(matches) == 0:
                matched_snapshots.append(snapshot)
        return matched_snapshots
