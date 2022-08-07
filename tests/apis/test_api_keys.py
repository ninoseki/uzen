from fastapi.testclient import TestClient


def test_api_key_verification(client_without_verity_api_key_override: TestClient):
    client = client_without_verity_api_key_override

    # create new API key
    res = client.post("/api/api_keys/new")
    assert res.status_code == 201

    data = res.json()
    api_key = data.get("apiKey")
    assert api_key is not None

    # it should raise 403 error (auth error)
    res = client.post("/api/snapshots/", json={})
    assert res.status_code == 403

    # it should raise 422 error (validation error)
    res = client.post("/api/snapshots/", json={}, headers={"api-key": api_key})
    assert res.status_code == 422

    # revoke API key
    res = client.post("/api/api_keys/revoke", json={"apiKey": api_key})
    assert res.status_code == 204

    # it should raise 403 error
    res = client.post("/api/snapshots/", json={}, headers={"api-key": api_key})
    assert res.status_code == 403

    # activate API key
    res = client.post("/api/api_keys/activate", json={"apiKey": api_key})
    assert res.status_code == 204

    # it should raise 422 error
    res = client.post("/api/snapshots/", json={}, headers={"api-key": api_key})
    assert res.status_code == 422
