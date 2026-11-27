"""
auth.py — logowanie oparte o sesję Flask (podpisane ciasteczko, bez stanu po
stronie serwera) i ograniczanie prób logowania.

Każdy chroniony endpoint wymaga w sesji user_id i tenant_id — to tenant_id
decyduje, jakie dane (zdarzenia, alerty) widzi użytkownik.

Limity prób (liczone w bazie, więc wspólne dla obu aplikacji i trwałe po
restarcie), okno 15 minut:
  * 5 błędnych prób dla pary (login, adres IP),
  * 20 błędnych prób z jednego adresu IP,
  * 30 błędnych prób na jeden login (ogranicza atak rozproszony na wiele IP,
    a jednocześnie nie pozwala jednej osobie zablokować cudzego konta na stałe).
Po przekroczeniu limitu logowanie jest odrzucane BEZ sprawdzania hasła.

Ograniczenie, które trzeba znać: sesje są bezstanowe (podpisane ciasteczko), więc
wylogowanie czyści tylko ciasteczko w przeglądarce — skradzionego ciasteczka nie
da się unieważnić przed końcem jego ważności (SOC_SESSION_HOURS).
"""

import logging
from functools import wraps

from flask import jsonify, redirect, render_template, request, session, url_for

import config
import db
import security

log = logging.getLogger("soc.auth")


def login_user(user):
    session.clear()  # nowa sesja po zalogowaniu (ochrona przed session fixation)
    session.permanent = True
    session["user_id"] = user["id"]
    session["tenant_id"] = user["tenant_id"]
    session["username"] = user["username"]
    session["role"] = user["role"]


def logout_user():
    session.clear()


def current_tenant_id():
    return session.get("tenant_id")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session or "tenant_id" not in session:
            if security.wants_json():
                return jsonify({"error": "Wymagane logowanie."}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


# ------------------------------------------------------------------ limity --

def _login_keys(username, ip):
    user = username.strip().lower()[:80]
    return f"up:{user}|{ip}", f"ip:{ip}", f"u:{user}"


def is_login_throttled(username, ip):
    pair, by_ip, by_user = _login_keys(username, ip)
    window = config.LOGIN_WINDOW_SECONDS
    return (
        db.count_auth_failures(pair, window) >= config.LOGIN_MAX_FAILURES_PER_USER_IP
        or db.count_auth_failures(by_ip, window) >= config.LOGIN_MAX_FAILURES_PER_IP
        or db.count_auth_failures(by_user, window) >= config.LOGIN_MAX_FAILURES_PER_USER
    )


def is_apikey_throttled(ip):
    return db.count_auth_failures(f"key:{ip}", config.LOGIN_WINDOW_SECONDS) >= config.APIKEY_MAX_FAILURES_PER_IP


def record_apikey_failure(ip):
    db.record_auth_failure(f"key:{ip}")


# ------------------------------------------------------------------ trasy ---

def register(app):
    """Dodaje /login i /logout (identyczne w obu aplikacjach)."""

    @app.route("/login", methods=["GET", "POST"])
    def login():
        next_url = security.safe_next(request.values.get("next"))
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()[:80]
            password = request.form.get("password") or ""
            ip = request.remote_addr or "unknown"

            if is_login_throttled(username, ip):
                log.warning("login_throttled user=%r ip=%s", username, ip)
                return render_template(
                    "login.html", next_url=next_url,
                    error="Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za 15 minut.",
                ), 429

            user = db.verify_user(username, password)
            if user:
                db.clear_auth_failures(_login_keys(username, ip)[0])
                login_user(user)
                log.info("login_ok user=%r tenant=%s ip=%s", username, user["tenant_id"], ip)
                safe_redirect_target = security.safe_next(next_url, default=url_for("login"))
                return redirect(safe_redirect_target)

            db.record_auth_failure(*_login_keys(username, ip))
            log.warning("login_failed user=%r ip=%s", username, ip)
            return render_template("login.html", error="Nieprawidłowy login lub hasło.", next_url=next_url), 401
        return render_template("login.html", error=None, next_url=next_url)

    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for("login"))
