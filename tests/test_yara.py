from uzen.yara import Yara


def test_scan():
    yara = Yara('rule foo: bar {strings: $a = "lmn" condition: $a}')
    matches = yara.scan("abcdefgjiklmnoprstuvwxyz")
    assert len(matches) == 1
