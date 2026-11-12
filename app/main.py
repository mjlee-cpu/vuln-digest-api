from fastapi import Depends, FastAPI, HTTPException, Query
from app import db 

app = FastAPI(title = "vuln-digest-api")

def get_conn():
    conn = db.connect()
    try:
        yield conn
    finally:
        conn.close()

@app.get("/health") 
#아래의 함수가 /health 경로로 들어오는 GET 요청 처리, 
#돌려준 dict나 list가 JSON으로 변환
def health():
    return {"status": "ok"}

@app.get("/vulnerabilities/recent")
def recent_vulnerabilities(limit: int = Query(50, ge=1, le=200),
                           conn=Depends(get_conn)):
    return db.recent(conn, limit=limit)

@app.get("/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str, conn=Depends(get_conn)):
    item = db.get_by_id(conn, cve_id.upper())
    if item is None:
            raise HTTPException(status_code=404, detail="not found")
    return item