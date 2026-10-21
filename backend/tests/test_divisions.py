from fastapi.testclient import TestClient


def test_divisions_lists_every_division_by_name(client: TestClient, election) -> None:
    response = client.get("/api/divisions")

    assert response.status_code == 200
    divisions = response.json()
    assert [d["name"] for d in divisions] == sorted(election.divisions)
    assert all(isinstance(d["id"], int) for d in divisions)
