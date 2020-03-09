from uzen.services.certificate import Certificate


def test_load_and_dump_from_url():
    assert "example.com" in Certificate.load_and_dump_from_url("https://example.com")
    assert Certificate.load_and_dump_from_url("http://example.com") == None
