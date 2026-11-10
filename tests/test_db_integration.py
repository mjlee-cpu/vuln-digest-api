"""DB 통합 테스트.

실제 PostgreSQL이 필요하다. 환경변수 DATABASE_URL이 없으면 전체를 건너뛴다.
(docker compose로 앱과 DB를 함께 띄우면 DATABASE_URL이 설정된다.)
"""

import os

import pytest

from app.cleaner import clean_kev_entry
from tests.samples import ZYXEL

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL이 없어 건너뜀"
)


@pytest.fixture
def db():
    # psycopg가 없는 환경(단위 테스트 단계)에서는 이 파일이 건너뛰어지므로 여기서 불러온다.
    from app import db as db_module

    return db_module


@pytest.fixture
def conn(db):
    """테스트마다 빈 테이블에서 시작하는 DB 연결."""
    connection = db.connect()
    db.init_schema(connection)
    connection.execute("TRUNCATE vulnerabilities")
    connection.commit()
    yield connection
    connection.close()


def make_item(cve_id, added_on, **overrides):
    raw = dict(ZYXEL, cveID=cve_id, dateAdded=added_on, **overrides)
    return clean_kev_entry(raw)


def test_saved_item_can_be_read_back(db, conn):
    item = make_item("CVE-2024-0001", "2024-01-01")
    assert db.upsert_items(conn, [item]) == 1
    assert db.get_by_id(conn, "CVE-2024-0001") == item


def test_unknown_id_returns_none(db, conn):
    assert db.get_by_id(conn, "CVE-1999-9999") is None


def test_saving_the_same_cve_twice_keeps_one_row_and_updates_it(db, conn):
    db.upsert_items(conn, [make_item("CVE-2024-0002", "2024-01-02")])
    db.upsert_items(conn, [make_item("CVE-2024-0002", "2024-01-02", vendorProject="Changed")])
    rows = db.recent(conn)
    assert len(rows) == 1
    assert rows[0]["vendor"] == "Changed"


def test_recent_is_newest_first_and_respects_limit(db, conn):
    db.upsert_items(
        conn,
        [
            make_item("CVE-2024-0003", "2024-01-03"),
            make_item("CVE-2024-0005", "2024-01-05"),
            make_item("CVE-2024-0004", "2024-01-04"),
        ],
    )
    ids = [row["cveId"] for row in db.recent(conn, limit=2)]
    assert ids == ["CVE-2024-0005", "CVE-2024-0004"]


def test_missing_due_date_is_stored_as_none(db, conn):
    db.upsert_items(conn, [make_item("CVE-2024-0006", "2024-01-06", dueDate="")])
    assert db.get_by_id(conn, "CVE-2024-0006")["dueDate"] is None


def test_links_and_cwes_round_trip(db, conn):
    item = make_item("CVE-2024-0007", "2024-01-07")
    db.upsert_items(conn, [item])
    saved = db.get_by_id(conn, "CVE-2024-0007")
    assert saved["links"] == item["links"]
    assert saved["cwes"] == item["cwes"]
