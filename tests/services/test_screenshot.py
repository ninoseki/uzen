from app.services.screenshot import get_not_found_png, get_screenshot_url


def test_get_not_found_png():
    assert isinstance(get_not_found_png(), bytes)


def test_get_screenshot_url():
    assert get_screenshot_url("test", "test") == "http://localhost:9000/test/test.png"
