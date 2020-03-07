import vcr
import socket
import pytest
import datetime


from uzen.services.urlscan import URLScan


@vcr.use_cassette("tests/fixtures/vcr_cassettes/urlscan_import.yaml")
def test_urlscan_import():
    snapshot = URLScan.import_as_snapshot(
        "e6d69372-b402-487a-9825-7e25cc15ce41")
    assert snapshot.url == "https://nnpub.org/"
    assert snapshot.ip_address == "162.215.240.128"
    assert (
        snapshot.server
        == "Apache/2.4.41 (cPanel) OpenSSL/1.1.1d mod_bwlimited/1.4 Phusion_Passenger/5.3.7"
    )
    assert snapshot.content_type == "text/html; charset=utf-8"
    assert isinstance(snapshot.created_at, datetime.datetime)
