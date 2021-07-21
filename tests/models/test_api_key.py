import pytest

from app import models


@pytest.mark.asyncio
async def test_create():
    key = models.APIKey()
    await key.save()

    assert key is not None
    assert key.id is not None
    assert key.last_queried_at is None
    assert key.is_active is True
    assert key.total_queries == 0


@pytest.mark.asyncio
async def test_revoke():
    key = models.APIKey()
    await key.save()

    assert key.is_active is True

    await key.revoke()
    assert key.is_active is False


@pytest.mark.asyncio
async def test_update_usage():
    key = models.APIKey()
    await key.save()

    assert key.last_queried_at is None
    assert key.total_queries == 0

    await key.update_usage()
    assert key.last_queried_at is not None
    assert key.total_queries == 1


@pytest.mark.asyncio
async def test_activate():
    key = models.APIKey()
    await key.save()

    await key.revoke()
    assert key.is_active is False

    await key.activate()
    assert key.is_active is True


@pytest.mark.asyncio
async def test_is_active_key():
    key = models.APIKey()
    await key.save()
    assert await models.APIKey.is_active_key(key.id) is True

    await key.revoke()
    assert await models.APIKey.is_active_key(key.id) is False

    await key.activate()
    assert await models.APIKey.is_active_key(key.id) is True
