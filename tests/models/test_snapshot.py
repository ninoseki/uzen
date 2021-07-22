import pytest

from app import models
from tests.helper import make_snapshot_wrapper


@pytest.mark.asyncio
async def test_save_with_api_keys_and_tags():
    api_key = models.APIKey()
    await api_key.save()

    tag_count = await models.Tag.count()
    assert tag_count == 0

    tag_names = ["foo", "bar"]

    # create snapshot
    wrapper = await make_snapshot_wrapper()
    snapshot = await models.Snapshot.save_snapshot(
        wrapper, api_key=api_key.id, tag_names=tag_names
    )
    assert snapshot.api_key_id == api_key.id

    tag_count = await models.Tag.count()
    assert tag_count == len(tag_names)
