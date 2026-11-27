import datetime as dt
import sqlite3

import pandas as pd
import pytest

import events
import ingest


# ------------------------------------------------------------------- events

def test_parse_timestamp_rejects_garbage():
    for bad in ("", "NaT", "nan", None, 12345, "wczoraj", "1999-01-01 00:00:00", "2999-01-01 00:00:00"):
        with pytest.raises(events.InvalidEvent):
            events.parse_timestamp(bad)


def test_parse_timestamp_timezone_to_naive():
    out = events.parse_timestamp("2026-01-02T10:00:00+00:00")
    assert out.tzinfo is None


def test_clean_text_strips_control_chars_and_limits():
    assert events.clean_text("ab\x00c\n", "actor") == "ab c"
    assert len(events.clean_text("x" * 500, "actor")) == events.MAX_TEXT
    with pytest.raises(events.InvalidEvent):
        events.clean_text("NULL", "actor")


# ------------------------------------------------------------------- ingest

def test_numeric_columns_are_not_mistaken_for_ip():
    df = pd.DataFrame({"a": [1.5, 2.25, 3.5], "b": [10, 11, 12]})
    assert not any(ingest._is_ip(v) for v in df["a"])
    assert ingest._is_ip("192.168.0.1") and not ingest._is_ip("999.1.1.1")


def test_autodetect_mapping_polish_columns():
    df = pd.DataFrame({
        "Czas": [f"2026-01-02 10:{i:02d}:00" for i in range(20)],
        "Uzytkownik": [f"user{i}" for i in range(20)],
        "Akcja": ["login"] * 20,
        "Adres IP": [f"192.168.1.{i + 1}" for i in range(20)],
        "Wynik": ["success"] * 20,
    })
    m = ingest.autodetect_mapping(df)["mapping"]
    assert m["timestamp"] == "Czas" and m["actor"] == "Uzytkownik" and m["ip"] == "Adres IP"


def test_apply_mapping_counts_rejected_rows():
    df = pd.DataFrame({"t": ["2026-01-02 10:00:00", "zły", None], "u": ["a", "b", "c"], "x": ["login"] * 3})
    rows, rejected = ingest.apply_mapping(df, {"timestamp": "t", "actor": "u", "action": "x"})
    assert len(rows) == 1 and rejected == 2


def test_validate_mapping():
    df = pd.DataFrame({"t": [1], "u": [1], "x": [1]})
    assert ingest.validate_mapping(df, {"timestamp": "t", "actor": "u", "action": "x"}) == []
    assert ingest.validate_mapping(df, {"timestamp": "t"})
    assert ingest.validate_mapping(df, "nie-słownik")
    assert ingest.validate_mapping(df, {"timestamp": "t", "actor": "u", "action": "brak"})


def test_load_dataframe_encodings_and_json(tmp_path):
    p = tmp_path / "a.csv"
    p.write_bytes("użytkownik;akcja\nżółć;login\n".encode("cp1250"))
    assert ingest.load_dataframe(str(p), "a.csv").iloc[0, 0] == "żółć"
    j = tmp_path / "a.json"
    j.write_text('{"data": [{"u": "a", "t": 1}]}')
    assert list(ingest.load_dataframe(str(j), "a.json").columns) == ["u", "t"]
    n = tmp_path / "n.csv"
    n.write_text("1,2\n3,4\n")
    assert all(isinstance(c, str) for c in ingest.load_dataframe(str(n), "n.csv").columns)


# ---------------------------------------------------------------------- db

def test_password_policy(db):
    t = db.create_tenant("X")
    with pytest.raises(ValueError):
        db.create_user(t, "someone", "krotkie")
    db.create_user(t, "someone", "wystarczajaco-dlugie")
    with pytest.raises(ValueError):
        db.create_user(t, "someone", "wystarczajaco-dlugie")
    assert db.verify_user("someone", "wystarczajaco-dlugie")
    assert not db.verify_user("someone", "zle-zle-zle-zle")
    assert not db.verify_user("nikt", "zle-zle-zle-zle")


def test_legacy_plaintext_api_key_migrated(tmp_path, monkeypatch):
    import db
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, sector TEXT,
            api_key TEXT, created_at TEXT NOT NULL);
        INSERT INTO tenants (name, api_key, created_at) VALUES ('Stary', 'legacy-plain-key-123456', '2025-01-01 00:00:00');
    """)
    conn.commit()
    conn.close()
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    assert db.get_tenant_by_api_key("legacy-plain-key-123456")["name"] == "Stary"
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT api_key FROM tenants").fetchone()[0] is None
    conn.close()


# ------------------------------------------------------------------ monitor

def _add(db, tenant, rows):
    db.insert_events_bulk(tenant, [events.normalize_event(*r) for r in rows])


def _row(actor, action, ts, ip="192.168.1.5", status="success", records=1):
    return (actor, action, ts, ip, status, records, dt.datetime(2026, 6, 1))


@pytest.fixture()
def monitor(db):
    import ai_monitor
    ai_monitor.STATE.clear()
    return ai_monitor


def test_bruteforce_rule_fires_and_alert_stored(db, monitor, two_tenants):
    a, _ = two_tenants
    rows = [_row("victim", "login", f"2026-01-02 10:00:{i:02d}", ip="10.9.9.9", status="failed") for i in range(10)]
    _add(db, a, rows)
    monitor.run_once()
    alerts = db.fetch_alerts(a, limit=50)
    assert any("RULE_BRUTEFORCE" in x["detectors"] for x in alerts)


def test_tenants_do_not_swallow_each_others_events(db, monitor, two_tenants):
    """Regresja: wspólny kursor seen_id powodował pomijanie zdarzeń drugiego tenanta."""
    a, b = two_tenants
    _add(db, a, [_row("x", "login", "2026-01-02 10:00:00")] * 5)
    monitor.run_once()
    _add(db, b, [_row("y", "login", f"2026-01-02 11:00:{i:02d}", ip="10.1.1.1", status="failed") for i in range(10)])
    monitor.run_once()
    assert any("RULE_BRUTEFORCE" in x["detectors"] for x in db.fetch_alerts(b, limit=50))
    assert db.fetch_alerts(a, limit=50) == [] or all(x["actor"] == "x" for x in db.fetch_alerts(a, limit=50))


def test_failing_tenant_does_not_block_others(db, monitor, two_tenants, monkeypatch):
    a, b = two_tenants
    _add(db, a, [_row("x", "login", "2026-01-02 10:00:00")])
    _add(db, b, [_row("y", "login", f"2026-01-02 11:00:{i:02d}", ip="10.1.1.1", status="failed") for i in range(10)])
    original = monitor._detect

    def boom(tenant_id, state, new_events):
        if tenant_id == a:
            raise RuntimeError("zatruty tenant")
        return original(tenant_id, state, new_events)

    monkeypatch.setattr(monitor, "_detect", boom)
    for _ in range(4):
        monitor.run_once()
    assert any("RULE_BRUTEFORCE" in x["detectors"] for x in db.fetch_alerts(b, limit=50))
    # po 3 nieudanych próbach partia jest pomijana, kursor idzie dalej
    assert db.get_monitor_cursor(a) >= 1


def test_cursor_persisted_across_restart(db, monitor, two_tenants):
    a, _ = two_tenants
    rows = [_row("v", "login", f"2026-01-02 10:00:{i:02d}", ip="10.9.9.9", status="failed") for i in range(10)]
    _add(db, a, rows)
    monitor.run_once()
    n = len(db.fetch_alerts(a, limit=500))
    monitor.STATE.clear()  # symulacja restartu procesu
    monitor.run_once()
    assert len(db.fetch_alerts(a, limit=500)) == n  # brak duplikatów alertów


def test_scoring_and_severity(monitor):
    ts = dt.datetime(2026, 1, 2, 3, 0, 0)
    score = monitor.calculate_score(3, ["RULE_NIGHT_PRIVILEGED"], "admin", ts, "delete_record")
    assert 0 < score <= 15
    assert monitor.severity_from_score(0) == "LOW"
    assert monitor.severity_from_score(15) == "CRITICAL"
    assert monitor.severity_from_score(score) in {"MEDIUM", "HIGH", "CRITICAL"}


def test_privileged_actors_configurable(monkeypatch, monitor):
    import config
    monkeypatch.setattr(config, "PRIVILEGED_ACTORS", {"szef"})
    ts = dt.datetime(2026, 1, 2, 3, 0, 0)
    assert monitor.calculate_score(0, [], "szef", ts, "login") > monitor.calculate_score(0, [], "admin", ts, "login")


def test_classify_attack_type(monitor):
    assert "atak siłowy" in monitor.classify_attack_type(["RULE_BRUTEFORCE"])
    assert monitor.classify_attack_type([]) == "Nieokreślona anomalia"
