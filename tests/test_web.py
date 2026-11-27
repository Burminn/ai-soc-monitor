import io

from conftest import PASSWORD, csrf, login


def ev(**kw):
    base = {"actor": "u1", "action": "login", "timestamp": "2026-01-02 10:00:00",
            "ip": "192.168.1.5", "status": "success", "records": 1}
    base.update(kw)
    return base


# ----------------------------------------------------------- uwierzytelnianie

def test_pages_require_login(bi, dash):
    assert bi[1].get("/").status_code == 302
    assert dash[1].get("/").status_code == 302
    assert dash[1].get("/api/alerts").status_code == 401
    assert bi[1].post("/ingest/preview").status_code in (401, 403)


def test_login_ok_and_wrong_password(bi):
    _, c = bi
    assert login(c, password="zle-haslo-zle-haslo").status_code == 401
    assert login(c).status_code == 302


def test_open_redirect_blocked(bi):
    _, c = bi
    for bad in ("https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)"):
        r = login(c, next_url=bad)
        assert r.status_code == 302
        assert r.headers["Location"] == "/", bad
        c.get("/logout")
    r = login(c, next_url="/ingest")
    assert r.headers["Location"] == "/ingest"


def test_login_throttling(bi):
    _, c = bi
    for _ in range(5):
        assert login(c, password="zle-haslo-zle-haslo").status_code == 401
    # po przekroczeniu limitu nawet poprawne hasło jest odrzucane (429)
    assert login(c).status_code == 429


def test_session_cookie_flags(bi):
    _, c = bi
    r = login(c)
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


# --------------------------------------------------------------------- CSRF

def test_csrf_required_for_post(bi):
    _, c = bi
    login(c)
    r = c.post("/ingest/commit", json={"token": "x", "mapping": {}})
    assert r.status_code == 403
    assert "CSRF" in r.get_json()["error"]


def test_csrf_required_for_login_form(bi):
    _, c = bi
    r = c.post("/login", data={"username": "alice", "password": PASSWORD})
    assert r.status_code == 403


# --------------------------------------------------------- nagłówki bezp.

def test_security_headers(bi):
    _, c = bi
    r = c.get("/login")
    h = r.headers
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    csp = h["Content-Security-Policy"]
    assert "script-src 'self' 'nonce-" in csp and "frame-ancestors 'none'" in csp
    assert "cdn" not in r.get_data(as_text=True).lower()


def test_csp_nonce_differs_per_request(bi):
    _, c = bi
    a = c.get("/login").headers["Content-Security-Policy"]
    b = c.get("/login").headers["Content-Security-Policy"]
    assert a != b


def test_healthz_public(bi):
    assert bi[1].get("/healthz").get_json() == {"status": "ok"}


# ---------------------------------------------------------------- API ingest

def _key(db, tenant_id):
    return db.rotate_api_key(tenant_id)


def test_api_ingest_requires_valid_key(bi, db, two_tenants):
    _, c = bi
    assert c.post("/api/v1/events", json=[ev()]).status_code == 401
    assert c.post("/api/v1/events", json=[ev()], headers={"X-API-Key": "soc_nieprawdziwy_klucz"}).status_code == 401


def test_api_ingest_rejects_bad_events(bi, db, two_tenants):
    a, _b = two_tenants
    key = _key(db, a)
    _, c = bi
    payload = [
        ev(),
        ev(timestamp="not-a-date"),
        ev(timestamp="NaT"),
        ev(timestamp=12345),
        ev(actor=""),
        "nie-obiekt",
        ev(timestamp="1970-01-01 00:00:00"),
        ev(timestamp="2999-01-01 00:00:00"),
    ]
    r = c.post("/api/v1/events", json=payload, headers={"X-API-Key": key})
    assert r.status_code == 201
    assert r.get_json() == {"inserted": 1, "skipped": 7}
    assert db.count_events(a) == 1


def test_api_ingest_normalizes(bi, db, two_tenants):
    a, _ = two_tenants
    key = _key(db, a)
    _, c = bi
    c.post("/api/v1/events", json=[ev(ip="nie-ip", status="FAILED", records=-5)], headers={"X-API-Key": key})
    row = db.fetch_recent_events(a, 5)[0]
    assert row["ip"] == "0.0.0.0" and row["status"] == "failed" and row["records"] == 0


def test_api_key_stored_hashed(db, two_tenants):
    a, _ = two_tenants
    key = _key(db, a)
    conn = db.get_conn()
    raw = conn.execute("SELECT * FROM tenants WHERE id=?", (a,)).fetchone()
    conn.close()
    assert key not in " ".join(str(v) for v in dict(raw).values())
    assert db.get_tenant_by_api_key(key)["id"] == a
    assert "api_key_hash" not in db.get_tenant(a)


def test_rotate_invalidates_old_key(db, two_tenants):
    a, _ = two_tenants
    old = _key(db, a)
    new = _key(db, a)
    assert db.get_tenant_by_api_key(old) is None
    assert db.get_tenant_by_api_key(new)["id"] == a


def test_api_key_failures_throttled(bi, db, two_tenants):
    _, c = bi
    codes = [c.post("/api/v1/events", json=[], headers={"X-API-Key": "soc_zly_klucz_zly_klucz"}).status_code
             for _ in range(32)]
    assert codes[0] == 401 and codes[-1] == 429


# ------------------------------------------------------ izolacja tenantów

def test_tenant_isolation_in_dashboard(bi, dash, db, two_tenants):
    a, b = two_tenants
    db.insert_alert(a, "victim_a", "login", "2026-01-02 10:00:00", "IsolationForest", 2, "x", 1, 5, "MEDIUM")
    db.insert_alert(b, "victim_b", "login", "2026-01-02 10:00:00", "IsolationForest", 2, "x", 1, 5, "MEDIUM")
    _, c = dash
    login(c, "alice")
    users = [x["user"] for x in c.get("/api/alerts").get_json()]
    assert users == ["victim_a"]
    # parametr tenant_id z żądania jest ignorowany
    users = [x["user"] for x in c.get("/api/alerts?tenant_id=2").get_json()]
    assert users == ["victim_a"]


# ------------------------------------------------------------ import plików

CSV = "Czas;Uzytkownik;Akcja;Adres IP;Wynik\n" + "\n".join(
    f"2026-01-02 10:{i:02d}:00;user{i};login;192.168.1.{i + 1};success" for i in range(20)
)


def _preview(c, text=CSV, name="log.csv"):
    return c.post("/ingest/preview", data={"file": (io.BytesIO(text.encode()), name)},
                  headers={"X-CSRF-Token": csrf(c)}, content_type="multipart/form-data")


def test_import_preview_and_commit(bi, db, two_tenants):
    a, _ = two_tenants
    _, c = bi
    login(c)
    r = _preview(c)
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert db.count_events(a) == 0  # podgląd niczego nie zapisuje
    r = c.post("/ingest/commit", json={"token": body["token"], "mapping": body["mapping"]},
               headers={"X-CSRF-Token": csrf(c)})
    assert r.status_code == 200 and r.get_json()["inserted"] == 20
    assert db.count_events(a) == 20


def test_import_token_bound_to_owner(bi, db, two_tenants):
    _, c = bi
    login(c, "alice")
    body = _preview(c).get_json()
    mod, other = bi[0], bi[0].app.test_client()
    login(other, "bob")
    r = other.post("/ingest/commit", json={"token": body["token"], "mapping": body["mapping"]},
                   headers={"X-CSRF-Token": csrf(other)})
    assert r.status_code == 400


def test_import_commit_rejects_bad_mapping(bi, db, two_tenants):
    _, c = bi
    login(c)
    body = _preview(c).get_json()
    r = c.post("/ingest/commit", json={"token": body["token"], "mapping": {"timestamp": "nie ma takiej"}},
               headers={"X-CSRF-Token": csrf(c)})
    assert r.status_code == 400


def test_demo_form_disabled_by_default(bi):
    _, c = bi
    login(c)
    r = c.post("/", data={"username": "x", "action": "login", "csrf_token": csrf(c)})
    assert r.status_code == 403


def test_compliance_report_pdf(dash, db, two_tenants):
    a, _ = two_tenants
    db.insert_alert(a, "u", "login", "2026-01-02 10:00:00", "RULE_BRUTEFORCE", 1, "Możliwy atak", 1, 9, "HIGH")
    _, c = dash
    login(c)
    r = c.get("/report/compliance?start=2026-01-01&end=2026-01-31")
    assert r.status_code == 200 and r.data.startswith(b"%PDF")
    assert c.get("/report/compliance?start=zle").status_code == 400
    assert c.get("/report/compliance?start=2020-01-01&end=2026-01-31").status_code == 400
