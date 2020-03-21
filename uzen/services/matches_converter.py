from typing import List
import yara

from uzen.models.schemas.yara import YaraMatch


def normalize(elem):
    if isinstance(elem, bytes):
        return elem.decode()

    return elem


def normalize_strings(tuples):
    results = []
    for tup in tuples:
        results.append([normalize(elem) for elem in tup])

    return results


class MatchesConverter:
    @staticmethod
    def convert(matches: List[yara.Match]) -> List[YaraMatch]:
        _matches = []
        for match in matches:
            _matches.append(
                YaraMatch(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=match.tags,
                    meta=match.meta,
                    strings=normalize_strings(match.strings),
                )
            )
        return _matches
