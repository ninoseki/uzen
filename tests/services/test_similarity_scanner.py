import pytest

from app.models.snapshot import Snapshot
from app.services.similarity_scanner import SimilarityScanner


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_scan():
    scanner = SimilarityScanner("<p>foo</p>")
    results = await scanner.scan_snapshots()
    assert len(results) == 0

    scanner = SimilarityScanner("<p>bar</p>")
    results = await scanner.scan_snapshots()
    assert len(results) == await Snapshot.all().count()

    scanner = SimilarityScanner("<p>bar</p>")
    results = await scanner.scan_snapshots(exclude_hostname="example.com")
    assert len(results) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_scan_with_threshold():
    scanner = SimilarityScanner(html="<div>foo</div>")
    results = await scanner.scan_snapshots()
    assert len(results) == 0

    scanner = SimilarityScanner(html="<div>foo</div>", threshold=0.0)
    results = await scanner.scan_snapshots()
    assert len(results) == await Snapshot.all().count()
