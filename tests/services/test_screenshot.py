from uzen.services.screenshot import get_not_found_png, get_screenshot_url


def test_get_not_found_png():
    assert get_not_found_png()


def test_get_screenshot_url():
    assert get_screenshot_url("test", "test") == "http://127.0.0.1:9000/test/test.png"
