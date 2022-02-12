from app.schemas.device import Device, get_devices


def test_get_devices():
    devices = get_devices()
    assert len(devices) > 0
    assert isinstance(devices[0], Device)
