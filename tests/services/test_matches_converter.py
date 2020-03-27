import yara

from uzen.services.matches_converter import MatchesConverter


def test_convert():
    rule = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')
    matches = rule.match(data="abcdefgjiklmnoprstuvwxyz")

    converted = MatchesConverter.convert(matches)
    assert isinstance(converted, list)

    first = converted[0]
    assert first.rule == "foo"
    assert first.namespace == "default"
    assert first.tags == ["bar"]
    assert first.meta == {}
    assert first.strings == [["10", "$a", "lmn"]]
