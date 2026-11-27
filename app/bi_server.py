"""
bi_server.py — wejście danych: trzy drogi wprowadzania zdarzeń z systemów klienta
oraz formularz demo.

  1. /ingest        — wgranie pliku CSV/JSON, podgląd auto-mapowania,
                       zatwierdzenie przez operatora (interfejs webowy).
  2. /api/v1/events  — integracja maszyna-maszyna: system klienta wysyła zdarzenia
                       w formacie kanonicznym, uwierzytelnione kluczem API tenanta
                       (nagłówek X-API-Key).
  3. collector.py    — osobny proces, który cyklicznie skanuje folder z eksportami
                       i importuje je silnikiem z ingest.py.

Każde zdarzenie, z każdej drogi, przechodzi przez events.normalize_event().
Port 5000.
"""

import datetime
import secrets
import threading
import time

from flask import Flask, jsonify, render_template, request, session

import auth
import config
import db
import events
import ingest
import security
from auth import current_tenant_id, login_required

app = Flask(__name__, template_folder="templates")
security.init_app(app)
auth.register(app)

db.init_db()


class PendingImports:
    """Pliki wgrane w kroku "podgląd", czekające na zatwierdzenie.

    Token jest losowy (nie do odgadnięcia) i przypisany do konkretnego użytkownika
    i tenanta: zatwierdzić import może tylko ten, kto go wgrał. Wpisy wygasają po
    15 minutach, a ich liczba jest ograniczona (plik w pamięci to DataFrame).
    Przechowywane w pamięci procesu — dlatego serwer działa w jednym procesie
    (gunicorn --workers 1, patrz Dockerfile).
    """

    TTL_SECONDS = 15 * 60
    MAX_TOTAL = 10
    MAX_PER_USER = 2

    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def _purge(self, now):
        for token in [t for t, i in self._items.items() if now - i["created"] > self.TTL_SECONDS]:
            del self._items[token]

    def put(self, user_id, tenant_id, df):
        """Zwraca token albo None, gdy serwer ma za dużo importów w toku."""
        now = time.time()
        with self._lock:
            self._purge(now)
            own = sorted((i["created"], t) for t, i in self._items.items() if i["user_id"] == user_id)
            while len(own) >= self.MAX_PER_USER:
                del self._items[own.pop(0)[1]]
            if len(self._items) >= self.MAX_TOTAL:
                return None
            token = secrets.token_urlsafe(24)
            self._items[token] = {"user_id": user_id, "tenant_id": tenant_id, "df": df, "created": now}
            return token

    def get(self, token, user_id, tenant_id):
        with self._lock:
            self._purge(time.time())
            item = self._items.get(token) if isinstance(token, str) else None
            if item and item["user_id"] == user_id and item["tenant_id"] == tenant_id:
                return item["df"]
            return None

    def discard(self, token):
        with self._lock:
            self._items.pop(token, None)


pending_imports = PendingImports()


# ------------------------------------------------------- formularz demo ----

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    tenant_id = current_tenant_id()
    tenant = db.get_tenant(tenant_id)

    def page(error=None, status=200):
        return render_template("index.html", tenant=tenant, username=session.get("username"),
                               demo_mode=config.DEMO_MODE, error=error), status

    if request.method == "POST":
        if not config.DEMO_MODE:
            return page("Formularz jest wyłączony (SOC_DEMO_MODE=0).", 403)
        try:
            event = events.normalize_event(
                actor=request.form.get("username"),
                action=request.form.get("action"),
                timestamp=datetime.datetime.now(),
                ip=request.remote_addr,
                status=request.form.get("status", "success"),
                records=request.form.get("records", "1"),
            )
        except events.InvalidEvent as exc:
            return page(f"Niepoprawne zdarzenie: {exc}.", 400)
        db.insert_events_bulk(tenant_id, [event])
        return page()

    return page()


# --------------------------------------------------------- smart import ---

@app.route("/ingest", methods=["GET"])
@login_required
def ingest_form():
    tenant = db.get_tenant(current_tenant_id())
    return render_template("ingest.html", tenant=tenant, username=session.get("username"))


@app.route("/ingest/preview", methods=["POST"])
@login_required
def ingest_preview():
    """Wgrywa plik, uruchamia autodetect_mapping, NIC nie zapisuje do bazy.
    Zwraca propozycję mapowania + próbkę wierszy do wizualnej weryfikacji."""
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "Brak pliku."}), 400

    try:
        df = ingest.load_dataframe(f, filename_hint=f.filename)
    except ValueError as exc:  # także błędy parsowania pandas / JSON
        return jsonify({"error": f"Nie udało się wczytać pliku: {str(exc)[:200]}"}), 400
    except Exception:  # noqa: BLE001
        return jsonify({"error": "Nie udało się wczytać pliku."}), 400

    if df.empty:
        return jsonify({"error": "Plik nie zawiera żadnych wierszy."}), 400

    result = ingest.autodetect_mapping(df)

    token = pending_imports.put(session["user_id"], current_tenant_id(), df)
    if token is None:
        return jsonify({"error": "Zbyt wiele importów w toku. Spróbuj za kilka minut."}), 503

    preview_rows, _ = ingest.apply_mapping(df.head(5), result["mapping"])

    return jsonify({
        "token": token,
        "columns": list(df.columns),
        "row_count": len(df),
        "mapping": result["mapping"],
        "confidence": result["confidence"],
        "unmapped_columns": result["unmapped_columns"],
        "auto_importable": result["auto_importable"],
        "warnings": result["warnings"],
        "preview_rows": preview_rows,
    })


@app.route("/ingest/commit", methods=["POST"])
@login_required
def ingest_commit():
    """Zapisuje do bazy zdarzenia z pliku, którego token dostaliśmy z
    /ingest/preview, z mapowaniem ewentualnie POPRAWIONYM ręcznie przez
    operatora (payload.mapping nadpisuje propozycję)."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Nieprawidłowe żądanie."}), 400
    token = payload.get("token")
    mapping = payload.get("mapping")
    tenant_id = current_tenant_id()

    df = pending_imports.get(token, session["user_id"], tenant_id)
    if df is None:
        return jsonify({"error": "Sesja importu wygasła — wgraj plik ponownie."}), 400

    errors = ingest.validate_mapping(df, mapping)
    if errors:
        return jsonify({"error": " ".join(errors)}), 400

    rows, rejected = ingest.apply_mapping(df, mapping)
    inserted = db.insert_events_bulk(tenant_id, rows)
    pending_imports.discard(token)

    return jsonify({"inserted": inserted, "rejected": rejected})


# --------------------------------------------------- API integracyjne -----

@app.route("/api/v1/events", methods=["POST"])
@security.csrf_exempt  # uwierzytelnianie kluczem API w nagłówku, bez ciasteczek
def api_ingest_events():
    """
    Integracja maszyna-maszyna. System klienta (albo collector.py) wysyła:

    Nagłówek: X-API-Key: <klucz tenanta>
    Body (JSON): lista obiektów w formacie kanonicznym:
        [{"actor": "...", "action": "...", "timestamp": "YYYY-MM-DD HH:MM:SS",
          "ip": "...", "status": "success|failed", "records": 0}, ...]

    Pola actor, action i timestamp są wymagane; zdarzenia o niepoprawnym kształcie
    są pomijane i zliczane w polu "skipped".
    """
    ip = request.remote_addr or "unknown"
    if auth.is_apikey_throttled(ip):
        return jsonify({"error": "Zbyt wiele nieudanych prób. Spróbuj później."}), 429

    tenant = db.get_tenant_by_api_key(request.headers.get("X-API-Key", ""))
    if not tenant:
        auth.record_apikey_failure(ip)
        return jsonify({"error": "Nieprawidłowy lub brakujący klucz API."}), 401

    payload = request.get_json(force=True, silent=True)
    if not isinstance(payload, list):
        return jsonify({"error": "Body musi być listą obiektów zdarzeń JSON."}), 400
    if len(payload) > 10000:
        return jsonify({"error": "Maksymalnie 10000 zdarzeń na jedno wywołanie."}), 400

    rows = []
    skipped = 0
    for item in payload:
        if not isinstance(item, dict):
            skipped += 1
            continue
        try:
            rows.append(events.normalize_event(
                actor=item.get("actor"),
                action=item.get("action"),
                timestamp=item.get("timestamp"),
                ip=item.get("ip"),
                status=item.get("status", "success"),
                records=item.get("records", 0),
            ))
        except events.InvalidEvent:
            skipped += 1

    inserted = db.insert_events_bulk(tenant["id"], rows)
    return jsonify({"inserted": inserted, "skipped": skipped}), 201


if __name__ == "__main__":
    # Tryb deweloperski. W kontenerze serwer startuje przez gunicorn (Dockerfile).
    app.run(host=config.HOST, port=5000, debug=False)
