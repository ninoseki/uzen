import pytest

from app.models.snapshot import Snapshot
from app.services.scanners import YaraScanner


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots")
async def test_scan():
    # it matches with all snapshots
    scanner = YaraScanner('rule foo: bar {strings: $a = "foo" condition: $a}')
    results = await scanner.scan_snapshots()
    assert len(results) == await Snapshot.all().count()

    scanner = YaraScanner('rule foo: bar {strings: $a = "nope" condition: $a}')
    results = await scanner.scan_snapshots()
    assert len(results) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts")
async def test_scan_against_script():
    # it matches with all snapshots
    scanner = YaraScanner('rule foo: bar {strings: $a = "foo" condition: $a}')
    results = await scanner.scan_snapshots(target="script")
    assert len(results) == await Snapshot.all().count()

    scanner = YaraScanner('rule foo: bar {strings: $a = "nope" condition: $a}')
    results = await scanner.scan_snapshots(target="script")
    assert len(results) == 0
