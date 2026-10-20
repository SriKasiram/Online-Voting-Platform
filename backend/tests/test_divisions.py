from fastapi.testclient import TestClient

from scripts.seed import CANDIDATES


def test_divisions_returns_the_seeded_divisions(client: TestClient) -> None:
    response = client.get("/api/divisions")

    assert response.status_code == 200
    divisions = response.json()
    assert [d["name"] for d in divisions] == sorted(CANDIDATES)
    assert all(isinstance(d["id"], int) for d in divisions)
