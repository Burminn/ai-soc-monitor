"""
security.py — wspólne zabezpieczenia obu aplikacji Flask (bi_server, ai_dashboard).

  * ciasteczko sesji: HttpOnly, SameSite=Lax, Secure (gdy SOC_HTTPS=1), ograniczony czas życia,
  * ochrona CSRF dla każdego żądania zmieniającego stan (token w sesji + nagłówek
    X-CSRF-Token albo pole formularza csrf_token); wyjątek: endpointy z kluczem API,
    które nie używają ciasteczek (@csrf_exempt),
  * nagłówki: Content-Security-Policy z nonce (blokuje wstrzyknięte skrypty i atrybuty
    onerror=... nawet gdyby gdzieś zabrakło escapowania), X-Frame-Options, nosniff,
    Referrer-Policy, HSTS za HTTPS,
  * ProxyFix, gdy aplikacja stoi za zaufanym reverse proxy (SOC_TRUSTED_PROXIES),
  * safe_next(): przekierowanie po logowaniu tylko na ścieżkę wewnątrz aplikacji.
"""

import datetime
import hmac
import logging
import secrets
from urllib.parse import unquote, urlparse

from flask import Response, current_app, g, jsonify, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

import config

CSRF_SESSION_KEY = "_csrf"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
JSON_PATH_PREFIXES = ("/api/", "/ingest/preview", "/ingest/commit")
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def csrf_exempt(view):
    """Oznacza endpoint, który nie używa ciasteczek sesji (np. API z kluczem)."""
    view.csrf_exempt = True
    return view


def wants_json():
    return request.path.startswith(JSON_PATH_PREFIXES)


def csrf_token():
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def csp_nonce():
    return getattr(g, "csp_nonce", "")


def deny(message, code):
    if wants_json():
        response = jsonify({"error": message})
        response.status_code = code
        return response
    return Response(message, status=code, mimetype="text/plain")


def safe_next(target, default="/"):
    """Zwraca `target` tylko wtedy, gdy jest ścieżką względną w obrębie aplikacji."""
    if not target or not isinstance(target, str):
        return default
    target = target.strip()
    if not target or len(target) > 300:
        return default

    decoded = unquote(target)
    if any(ord(c) < 32 for c in decoded) or "\\" in decoded:
        return default

    parsed = urlparse(decoded)
    if parsed.scheme or parsed.netloc:
        return default
    if not decoded.startswith("/") or decoded.startswith("//"):
        return default
    return decoded


def _before_request():
    g.csp_nonce = secrets.token_urlsafe(16)
    if request.method not in UNSAFE_METHODS:
        return None
    view = current_app.view_functions.get(request.endpoint)
    if view is not None and getattr(view, "csrf_exempt", False):
        return None
    expected = session.get(CSRF_SESSION_KEY, "")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
    if not expected or not hmac.compare_digest(expected, supplied):
        return deny("Nieprawidłowy lub brakujący token CSRF. Odśwież stronę i spróbuj ponownie.", 403)
    return None


def _after_request(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{csp_nonce()}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    if config.SESSION_COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def init_app(app):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    app.secret_key = config.require_secret_key()
    app.config.update(
        SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=config.SESSION_HOURS),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    )
    if config.TRUSTED_PROXIES > 0:
        n = config.TRUSTED_PROXIES
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    app.jinja_env.globals.update(csrf_token=csrf_token, csp_nonce=csp_nonce)
    app.before_request(_before_request)
    app.after_request(_after_request)

    @app.errorhandler(413)
    def too_large(_error):
        return deny("Plik jest za duży (limit 25 MB).", 413)

    @app.get("/healthz")
    @csrf_exempt
    def healthz():
        return jsonify({"status": "ok"})
