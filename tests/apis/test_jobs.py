import httpx
import pytest


@pytest.mark.asyncio
async def test_running_jobs(client: httpx.AsyncClient):
    job_names = ["yara", "snapshots", "similarity"]
    for name in job_names:
        response = await client.get(f"/api/jobs/{name}/running")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_job_id_validation(client: httpx.AsyncClient):
    job_names = ["yara", "snapshots", "similarity"]
    for name in job_names:
        response = await client.get(f"/api/jobs/{name}/foo")
        assert response.status_code == 422
