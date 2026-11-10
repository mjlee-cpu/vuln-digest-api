"""PostgreSQL 저장과 조회.

정제된 항목(app.cleaner의 결과)을 DB에 넣고 꺼낸다.
접속 주소는 환경변수 DATABASE_URL로 받는다.
"""

import os
from datetime import date

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id          TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL,
    product         TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL,
    added_on        DATE NOT NULL,
    due_date        DATE,
    required_action TEXT NOT NULL,
    ransomware_use  BOOLEAN NOT NULL,
    cwes            TEXT[] NOT NULL,
    links           JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_added_on
    ON vulnerabilities (added_on DESC);
"""

UPSERT = """
INSERT INTO vulnerabilities (
    cve_id, vendor, product, name, description, added_on, due_date,
    required_action, ransomware_use, cwes, links
) VALUES (
    %(cveId)s, %(vendor)s, %(product)s, %(name)s, %(description)s,
    %(addedOn)s, %(dueDate)s, %(requiredAction)s, %(ransomwareUse)s,
    %(cwes)s, %(links)s
)
ON CONFLICT (cve_id) DO UPDATE SET
    vendor = EXCLUDED.vendor,
    product = EXCLUDED.product,
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    added_on = EXCLUDED.added_on,
    due_date = EXCLUDED.due_date,
    required_action = EXCLUDED.required_action,
    ransomware_use = EXCLUDED.ransomware_use,
    cwes = EXCLUDED.cwes,
    links = EXCLUDED.links
"""

COLUMNS = (
    "cve_id AS \"cveId\", vendor, product, name, description, "
    "added_on AS \"addedOn\", due_date AS \"dueDate\", "
    "required_action AS \"requiredAction\", "
    "ransomware_use AS \"ransomwareUse\", cwes, links"
)


def connect(url=None):
    """DB에 연결한다. url이 없으면 환경변수 DATABASE_URL을 쓴다."""
    url = url or os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL 환경변수가 필요합니다.")
    return psycopg.connect(url, row_factory=dict_row)


def init_schema(conn):
    """테이블이 없으면 만든다. 여러 번 실행해도 안전하다."""
    conn.execute(SCHEMA)
    conn.commit()


def _to_date(value):
    return date.fromisoformat(value) if value else None


def upsert_items(conn, items):
    """항목을 저장한다. 같은 CVE가 있으면 내용을 갱신한다. 처리한 개수를 돌려준다."""
    count = 0
    with conn.cursor() as cur:
        for item in items:
            params = dict(
                item,
                addedOn=_to_date(item["addedOn"]),
                dueDate=_to_date(item.get("dueDate")),
                links=Jsonb(item["links"]),
            )
            cur.execute(UPSERT, params)
            count += 1
    conn.commit()
    return count


def _to_output(row):
    if row is None:
        return None
    out = dict(row)
    out["addedOn"] = out["addedOn"].isoformat()
    out["dueDate"] = out["dueDate"].isoformat() if out["dueDate"] else None
    return out


def recent(conn, limit=50):
    """최근에 추가된 순서로 최대 limit개를 돌려준다."""
    rows = conn.execute(
        f"SELECT {COLUMNS} FROM vulnerabilities "
        "ORDER BY added_on DESC, cve_id DESC LIMIT %s",
        (limit,),
    ).fetchall()
    return [_to_output(row) for row in rows]


def get_by_id(conn, cve_id):
    """CVE ID로 한 건을 찾는다. 없으면 None."""
    row = conn.execute(
        f"SELECT {COLUMNS} FROM vulnerabilities WHERE cve_id = %s",
        (cve_id,),
    ).fetchone()
    return _to_output(row)
