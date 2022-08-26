from app.dataclasses.ip2asn import IP2ASNResponse


def test_post_init():
    res = IP2ASNResponse("1.1.1.1", "dummy", "Unknown", "dummy")
    assert res.country_code == ""
