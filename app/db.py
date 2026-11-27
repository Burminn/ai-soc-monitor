"""
db.py — warstwa dostępu do danych (SQLite, tryb WAL).

Tryb WAL pozwala procesowi wstrzykującemu zdarzenia (bi_server), analizującemu
(ai_monitor) i dashboardowi (ai_dashboard) czytać i pisać równolegle.

KAŻDY rekord (użytkownik, zdarzenie, alert) jest przypisany do tenant_id:
jedna instalacja obsługuje wielu klientów, a zapytania o zdarzenia i alerty
zawsze przyjmują tenant_id i filtrują po nim.

Sekrety: hasła są przechowywane jako hash (werkzeug, scrypt), klucze API jako
SHA-256 (klucz ma 256 bitów losowości, więc szybki hash bez soli wystarcza).
Jawny klucz widać tylko raz, w chwili wygenerowania.
"""

import datetime
import hashlib
import os
import re
import secrets
import sqlite3
import time

from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("SOC_DB_PATH") or os.path.join(BASE_DIR, "data", "soc.db")

MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 256
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,80}$")
ROLES = ("operator",)  # role są zapisywane, ale jeszcze nie egzekwowane (patrz README)
API_KEY_PREFIX = "soc_"

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    sector          TEXT,
    created_at      TEXT NOT NULL,
    api_key_hash    TEXT,
    api_key_prefix  TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'operator',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    ip          TEXT,
    status      TEXT NOT NULL DEFAULT 'success',
    records     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id, id);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    detectors   TEXT,
    votes       INTEGER NOT NULL DEFAULT 0,
    attack_type TEXT,
    records     INTEGER NOT NULL DEFAULT 0,
    score       INTEGER NOT NULL DEFAULT 0,
    severity    TEXT NOT NULL DEFAULT 'LOW',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id, id);

CREATE TABLE IF NOT EXISTS monitor_state (
    tenant_id       INTEGER PRIMARY KEY REFERENCES tenants(id),
    last_event_id   INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_failures (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    key     TEXT NOT NULL,
    ts      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_failures ON auth_failures(key, ts);
"""


def get_conn():
    directory = os.path.dirname(DB_PATH)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass  # np. system plików bez uprawnień unixowych
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()
    conn.close()


def _hash_key(api_key):
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _migrate(conn):
    """Migracje schematu dla baz utworzonych starszymi wersjami (bez utraty danych)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(tenants)").fetchall()}
    if "api_key_hash" not in cols:
        conn.execute("ALTER TABLE tenants ADD COLUMN api_key_hash TEXT")
    if "api_key_prefix" not in cols:
        conn.execute("ALTER TABLE tenants ADD COLUMN api_key_prefix TEXT")

    # Starsze wersje trzymały klucz API jawnym tekstem w kolumnie api_key:
    # zamieniamy go na hash i kasujemy jawną wartość.
    if "api_key" in cols:
        rows = conn.execute(
            "SELECT id, api_key FROM tenants WHERE api_key IS NOT NULL AND api_key <> '' "
            "AND api_key_hash IS NULL"
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE tenants SET api_key_hash=?, api_key_prefix=?, api_key=NULL WHERE id=?",
                (_hash_key(row["api_key"]), row["api_key"][:8], row["id"]),
            )

    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_key_hash "
        "ON tenants(api_key_hash) WHERE api_key_hash IS NOT NULL"
    )


def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- tenants --

def create_tenant(name, sector=None):
    name = (name or "").strip()
    if not name or len(name) > 120:
        raise ValueError("Nazwa tenanta musi mieć od 1 do 120 znaków.")
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO tenants (name, sector, created_at) VALUES (?, ?, ?)",
        (name, sector, now_iso()),
    )
    conn.commit()
    tenant_id = cur.lastrowid
    conn.close()
    return tenant_id


def rotate_api_key(tenant_id):
    """Generuje nowy klucz API tenanta (stary przestaje działać). Zwraca jawny
    klucz — to jedyny moment, w którym da się go zobaczyć."""
    new_key = API_KEY_PREFIX + secrets.token_urlsafe(32)
    conn = get_conn()
    cur = conn.execute(
        "UPDATE tenants SET api_key_hash=?, api_key_prefix=? WHERE id=?",
        (_hash_key(new_key), new_key[:8], tenant_id),
    )
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        raise ValueError(f"Brak tenanta o id={tenant_id}.")
    return new_key


_TENANT_COLUMNS = "id, name, sector, created_at, api_key_prefix"


def get_tenant_by_api_key(api_key):
    if not isinstance(api_key, str) or not (10 <= len(api_key) <= 200):
        return None
    conn = get_conn()
    row = conn.execute(
        f"SELECT {_TENANT_COLUMNS} FROM tenants WHERE api_key_hash=?", (_hash_key(api_key),)
    ).fetchone()  # nosec B608 - stała lista kolumn, wartość przez parametr
    conn.close()
    return dict(row) if row else None


def list_tenants():
    conn = get_conn()
    rows = conn.execute(
        f"SELECT {_TENANT_COLUMNS} FROM tenants ORDER BY id"
    ).fetchall()  # nosec B608
    conn.close()
    return [dict(r) for r in rows]


def get_tenant(tenant_id):
    conn = get_conn()
    row = conn.execute(
        f"SELECT {_TENANT_COLUMNS} FROM tenants WHERE id=?", (tenant_id,)
    ).fetchone()  # nosec B608
    conn.close()
    return dict(row) if row else None


# ------------------------------------------------------------------ users --

def create_user(tenant_id, username, password, role="operator"):
    if not USERNAME_RE.match(username or ""):
        raise ValueError("Login: 3–80 znaków (litery, cyfry, _ . @ -).")
    if not isinstance(password, str) or not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise ValueError(f"Hasło musi mieć od {MIN_PASSWORD_LEN} do {MAX_PASSWORD_LEN} znaków.")
    if role not in ROLES:
        raise ValueError(f"Nieznana rola. Dozwolone: {', '.join(ROLES)}.")
    if get_tenant(tenant_id) is None:
        raise ValueError(f"Brak tenanta o id={tenant_id}.")

    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (tenant_id, username, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (tenant_id, username, generate_password_hash(password), role, now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("Użytkownik o takim loginie już istnieje.")
    finally:
        conn.close()


_dummy_hash = None


def _get_dummy_hash():
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = generate_password_hash(secrets.token_hex(16))
    return _dummy_hash


def verify_user(username, password):
    """Zwraca słownik użytkownika albo None. Dla nieistniejącego loginu też liczy
    hash, żeby czas odpowiedzi nie zdradzał, które loginy istnieją."""
    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LEN:
        return None
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if row is None:
        check_password_hash(_get_dummy_hash(), password)
        return None
    if check_password_hash(row["password_hash"], password):
        return dict(row)
    return None


# ------------------------------------------------- limity prób uwierzytelnienia --

def record_auth_failure(*keys):
    now = time.time()
    conn = get_conn()
    conn.executemany("INSERT INTO auth_failures (key, ts) VALUES (?, ?)", [(k, now) for k in keys])
    conn.execute("DELETE FROM auth_failures WHERE ts < ?", (now - 86400,))
    conn.commit()
    conn.close()


def count_auth_failures(key, window_seconds):
    conn = get_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM auth_failures WHERE key=? AND ts>?",
        (key, time.time() - window_seconds),
    ).fetchone()
    conn.close()
    return row["c"]


def clear_auth_failures(key):
    conn = get_conn()
    conn.execute("DELETE FROM auth_failures WHERE key=?", (key,))
    conn.commit()
    conn.close()


# ----------------------------------------------------------------- events --

def insert_event(tenant_id, actor, action, timestamp, ip, status="success", records=1):
    conn = get_conn()
    conn.execute(
        "INSERT INTO events (tenant_id, actor, action, timestamp, ip, status, records, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (tenant_id, actor, action, timestamp, ip, status, records, now_iso()),
    )
    conn.commit()
    conn.close()


def insert_events_bulk(tenant_id, rows):
    """rows: lista dictów z kluczami actor, action, timestamp, ip, status, records
    (po events.normalize_event). Jeden commit na cały batch."""
    if not rows:
        return 0
    conn = get_conn()
    created_at = now_iso()
    conn.executemany(
        "INSERT INTO events (tenant_id, actor, action, timestamp, ip, status, records, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(tenant_id, r["actor"], r["action"], r["timestamp"], r["ip"], r["status"],
          int(r["records"]), created_at) for r in rows],
    )
    conn.commit()
    conn.close()
    return len(rows)


def fetch_events_since(tenant_id, since_id):
    """Nowe zdarzenia danego tenanta o id > since_id, rosnąco."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM events WHERE tenant_id=? AND id>? ORDER BY id ASC",
        (tenant_id, since_id),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_recent_events(tenant_id, limit=5000):
    """Ostatnie N zdarzeń tenanta (do trenowania modeli), rosnąco po id."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM (SELECT * FROM events WHERE tenant_id=? ORDER BY id DESC LIMIT ?) "
        "ORDER BY id ASC",
        (tenant_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_events(tenant_id):
    conn = get_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE tenant_id=?", (tenant_id,)
    ).fetchone()
    conn.close()
    return row["c"]


def max_event_id(tenant_id):
    conn = get_conn()
    row = conn.execute(
        "SELECT COALESCE(MAX(id),0) AS m FROM events WHERE tenant_id=?", (tenant_id,)
    ).fetchone()
    conn.close()
    return row["m"]


# ---------------------------------------------------------- stan monitora --

def get_monitor_cursor(tenant_id):
    """Id ostatniego zdarzenia przetworzonego przez monitor (0 = jeszcze nic).
    Bez tego restart monitora przetwarzałby całą historię od nowa i dublował alerty."""
    conn = get_conn()
    row = conn.execute(
        "SELECT last_event_id FROM monitor_state WHERE tenant_id=?", (tenant_id,)
    ).fetchone()
    conn.close()
    return row["last_event_id"] if row else 0


def set_monitor_cursor(tenant_id, last_event_id):
    conn = get_conn()
    conn.execute(
        "INSERT INTO monitor_state (tenant_id, last_event_id, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(tenant_id) DO UPDATE SET last_event_id=excluded.last_event_id, "
        "updated_at=excluded.updated_at",
        (tenant_id, last_event_id, now_iso()),
    )
    conn.commit()
    conn.close()


def known_actor_ips(tenant_id, up_to_id):
    """Pary (actor, ip) widziane do wskazanego zdarzenia włącznie — do odtworzenia
    reguły "nowy adres IP" po restarcie monitora."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT DISTINCT actor, ip FROM events WHERE tenant_id=? AND id<=? AND ip IS NOT NULL",
        (tenant_id, up_to_id),
    ).fetchall()
    conn.close()
    return [(r["actor"], r["ip"]) for r in rows]


# ----------------------------------------------------------------- alerts --

def insert_alert(tenant_id, actor, action, timestamp, detectors, votes, attack_type, records, score, severity):
    conn = get_conn()
    conn.execute(
        "INSERT INTO alerts (tenant_id, actor, action, timestamp, detectors, votes, "
        "attack_type, records, score, severity, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (tenant_id, actor, action, timestamp, detectors, votes, attack_type, records,
         score, severity, now_iso()),
    )
    conn.commit()
    conn.close()


def fetch_alerts(tenant_id, limit=1000):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
        (tenant_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_alerts_between(tenant_id, start_iso, end_iso):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE tenant_id=? AND timestamp>=? AND timestamp<=? "
        "ORDER BY timestamp ASC",
        (tenant_id, start_iso, end_iso),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
