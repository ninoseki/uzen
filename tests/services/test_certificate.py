from app.services.certificate import Certificate


def test_load_from_url_with_http_website():
    assert Certificate.load_from_url("http://example.com") is None


def test_load_from_url_with_https_website():
    certificate = Certificate.load_from_url("https://example.com")
    assert certificate
    assert len(certificate.fingerprint) == 64
