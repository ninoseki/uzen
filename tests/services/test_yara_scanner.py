import pytest

from uzen.models.snapshots import Snapshot
from uzen.services.yara_scanner import YaraScanner


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_scan():
    # it matches with all snapshots
    scanner = YaraScanner('rule foo: bar {strings: $a = "foo" condition: $a}')
    results = await scanner.scan_snapshots()
    assert len(results) == await Snapshot.all().count()

    scanner = YaraScanner('rule foo: bar {strings: $a = "nope" condition: $a}')
    results = await scanner.scan_snapshots()
    assert len(results) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts_setup")
async def test_scan_against_script():
    # it matches with all snapshots
    scanner = YaraScanner('rule foo: bar {strings: $a = "foo" condition: $a}')
    results = await scanner.scan_snapshots(target="script")
    assert len(results) == await Snapshot.all().count()

    scanner = YaraScanner('rule foo: bar {strings: $a = "nope" condition: $a}')
    results = await scanner.scan_snapshots(target="script")
    assert len(results) == 0
