"""
ai_dashboard.py — dashboard BI + API dla frontendu + generator raportu zgodności PDF.

Każdy endpoint API zwraca WYŁĄCZNIE dane tenanta zalogowanego operatora
(tenant_id pochodzi z sesji, nigdy z parametrów żądania). Port 5001.
"""

import datetime
import io
import re
from collections import Counter, defaultdict

from flask import Flask, jsonify, render_template, request, send_file, session

import auth
import compliance
import config
import db
import security
from auth import current_tenant_id, login_required

app = Flask(__name__, template_folder="templates")
security.init_app(app)
auth.register(app)

db.init_db()

MAX_REPORT_DAYS = 366


@app.route("/api/alerts")
@login_required
def alerts():
    rows = db.fetch_alerts(current_tenant_id(), limit=2000)
    out = [{
        "user": r["actor"],
        "action": r["action"],
        "timestamp": r["timestamp"],
        "detectors": r["detectors"],
        "votes": r["votes"],
        "attack_type": r["attack_type"] or "Nieokreślona anomalia",
        "records": r["records"],
        "score": r["score"],
        "severity": r["severity"],
    } for r in rows]
    return jsonify(out), 200


@app.route("/api/stats")
@login_required
def stats():
    rows = db.fetch_alerts(current_tenant_id(), limit=5000)
    counts = defaultdict(int)
    for r in rows:
        try:
            hour = datetime.datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H")
        except ValueError:
            continue
        counts[hour] += 1
    return jsonify(dict(sorted(counts.items())))


@app.route("/api/attack_types")
@login_required
def attack_types():
    rows = db.fetch_alerts(current_tenant_id(), limit=5000)
    counts = Counter(r["attack_type"] or "Nieokreślona anomalia" for r in rows)
    return jsonify(dict(counts))


def _date_arg(name, default):
    raw = request.args.get(name)
    if raw is None:
        return default
    return datetime.date.fromisoformat(raw)  # ValueError -> obsłużone w trasie


@app.route("/report/compliance")
@login_required
def report_compliance():
    """
    Generuje raport zgodności PDF za podany okres (domyślnie: bieżący miesiąc).
    Parametry query: ?start=YYYY-MM-DD&end=YYYY-MM-DD
    """
    tenant_id = current_tenant_id()
    tenant = db.get_tenant(tenant_id)

    today = datetime.date.today()
    try:
        start = _date_arg("start", today.replace(day=1))
        end = _date_arg("end", today)
    except ValueError:
        return jsonify({"error": "Daty muszą mieć format RRRR-MM-DD."}), 400
    if start > end or (end - start).days > MAX_REPORT_DAYS:
        return jsonify({"error": f"Zakres dat: start <= end, najwyżej {MAX_REPORT_DAYS} dni."}), 400

    alerts_rows = db.fetch_alerts_between(tenant_id, f"{start} 00:00:00", f"{end} 23:59:59")
    pdf_bytes = compliance.build_compliance_pdf(
        tenant, alerts_rows, start.isoformat(), end.isoformat(),
        generated_by=session.get("username", "system"),
    )

    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", tenant["name"])[:60].strip("_") or "tenant"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"raport-zgodnosci-{safe_name}-{start}_{end}.pdf",
    )


@app.route("/")
@login_required
def index():
    tenant = db.get_tenant(current_tenant_id())
    return render_template("dashboard.html", tenant=tenant, username=session.get("username"))


if __name__ == "__main__":
    app.run(host=config.HOST, port=5001, debug=False)
