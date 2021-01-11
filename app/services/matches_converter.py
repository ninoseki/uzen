from typing import List

import yara

from app.schemas.yara import YaraMatch, YaraMatchString


def convert_strings(strings) -> List[YaraMatchString]:
    # strintgs is a list of tuple
    # (<offset>, <string identifier>, <string data>)
    # e.g. (81L, '$a', 'abc'),
    models = []
    for tuple_ in strings:
        items = list(tuple_)
        offset = int(items[0])
        identifier = items[1]
        data = items[2].decode()
        models.append(
            YaraMatchString(
                offset=offset, string_identifier=identifier, string_data=data
            )
        )

    return models


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
                    strings=convert_strings(match.strings),
                )
            )
        return _matches
