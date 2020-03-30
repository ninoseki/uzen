from typing import List

import yara

from uzen.models.schemas.yara import YaraMatch


def convert_strings_to_dict_items(strings) -> List[dict]:
    # strintgs is a list of tuple
    # (<offset>, <string identifier>, <string data>)
    # e.g. (81L, '$a', 'abc'),
    dict_items = []
    for tuple_ in strings:
        items = list(tuple_)
        offset = int(items[0])
        identifier = items[1]
        data = items[2].decode()
        dict_items.append(
            {"offset": offset, "string_identifier": identifier, "string_data": data}
        )

    return dict_items


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
                    strings=convert_strings_to_dict_items(match.strings),
                )
            )
        return _matches
