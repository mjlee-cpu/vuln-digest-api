import os

import pytest


@pytest.fixture 
def db():
    from app import db as db_module
    return db_module 

@pytest.fixture 
def conn(db):
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL이 없어 건너뜀")
    connection = db.connect() 
    db.init_schema(connection)
    connection.execute("TRUNCATE vulnerabilities")
    connection.commit() 
    yield connection 
    connection.close() 
    