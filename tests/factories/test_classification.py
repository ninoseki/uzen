import pytest
import vcr

from app.factories.classification import ClassificationFactory
from tests.helper import make_snapshot


@pytest.mark.asyncio
@vcr.use_cassette(
    "tests/fixtures/vcr_cassettes/classifications.yaml",
    filter_query_parameters=["key"],
    filter_headers=["x-apikey"],
)
async def test_build_from_snapshot():
    snapshot = make_snapshot()

    classifications = await ClassificationFactory.from_snapshot(snapshot)

    assert len(classifications) > 0

    first = classifications[0]
    assert not first.malicious
