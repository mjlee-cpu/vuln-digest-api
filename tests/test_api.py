import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.samples import make_item

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_recent_is_newest_first(db, conn):
    db.upsert_items(
        conn,
        [
            make_item("CVE-2024-0001", "2024-01-01"),
            make_item("CVE-2024-0003", "2024-01-03"),
            make_item("CVE-2024-0002", "2024-01-02"),
        ],
    )
    response = client.get("/vulnerabilities/recent")
    assert response.status_code == 200
    ids = [item["cveId"] for item in response.json()]
    assert ids == ["CVE-2024-0003", "CVE-2024-0002", "CVE-2024-0001"]


def test_recent_respects_limit(db, conn):
    db.upsert_items(
        conn,
        [make_item(f"CVE-2024-000{i}", f"2024-01-0{i}") for i in range(1, 4)],
    )
    response = client.get("/vulnerabilities/recent?limit=2")
    assert len(response.json()) == 2


@pytest.mark.usefixtures("conn")
def test_recent_rejects_invalid_limit():
    response = client.get("/vulnerabilities/recent?limit=0")
    assert response.status_code == 422


def test_get_returns_the_item(db, conn):
    item = make_item("CVE-2024-0001", "2024-01-01")
    db.upsert_items(conn, [item])
    response = client.get("/vulnerabilities/CVE-2024-0001")
    assert response.status_code == 200
    assert response.json() == item


def test_get_accepts_lower_case_id(db, conn):
    db.upsert_items(conn, [make_item("CVE-2024-0001", "2024-01-01")])
    response = client.get("/vulnerabilities/cve-2024-0001")
    assert response.status_code == 200


@pytest.mark.usefixtures("conn")
def test_get_unknown_id_returns_404():
    response = client.get("/vulnerabilities/CVE-1999-9999")
    assert response.status_code == 404