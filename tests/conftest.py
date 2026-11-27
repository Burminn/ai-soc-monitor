import importlib
import os
import sys

import pytest

APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP_DIR))
os.environ.setdefault("SOC_SECRET_KEY", "test-secret-key-test-secret-key-0123456789")

PASSWORD = "correct-horse-battery"


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "soc.db"))
    dbmod.init_db()
    import auth
    return dbmod


@pytest.fixture()
def two_tenants(db):
    a = db.create_tenant("Firma A", "test")
    b = db.create_tenant("Firma B", "test")
    db.create_user(a, "alice", PASSWORD)
    db.create_user(b, "bob", PASSWORD)
    return a, b


def _client(module_name):
    mod = importlib.import_module(module_name)
    mod.app.config["TESTING"] = True
    return mod, mod.app.test_client()


@pytest.fixture()
def bi(db, two_tenants):
    return _client("bi_server")


@pytest.fixture()
def dash(db, two_tenants):
    return _client("ai_dashboard")


def login(client, user="alice", password=PASSWORD, next_url=None):
    client.get("/login")
    with client.session_transaction() as s:
        token = s.get("_csrf")
    if token is None:
        client.get("/login")
        with client.session_transaction() as s:
            token = s.get("_csrf")
    data = {"username": user, "password": password, "csrf_token": token}
    if next_url:
        data["next"] = next_url
    return client.post("/login", data=data)


def csrf(client):
    with client.session_transaction() as s:
        token = s.get("_csrf")
    if token is None:
        client.get("/ingest")  # strona z meta csrf-token generuje token jak w przeglądarce
        with client.session_transaction() as s:
            token = s["_csrf"]
    return token
