"""
config.py — ustawienia współdzielone przez wszystkie procesy (konfiguracja
wyłącznie ze zmiennych środowiskowych, nic nie jest zapisane w repozytorium).

SOC_SECRET_KEY musi być identyczny w bi_server.py i ai_dashboard.py (lokalnie,
na jednym hoście, sesja z jednej aplikacji jest wtedy rozpoznawana w drugiej;
za proxy z osobnymi subdomenami operator loguje się osobno do każdej).
Brak klucza (albo klucz krótszy niż 32 znaki) kończy się błędem już przy starcie: wcześniejsza wersja prototypu przechodziła wtedy na
stały klucz deweloperski, co przy pomyłce we wdrożeniu pozwalało fałszować
sesje.

Wygenerowanie klucza:
    python -c "import secrets; print(secrets.token_hex(32))"
"""

import os

MIN_SECRET_LEN = 32


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        raise RuntimeError(f"Zmienna {name} musi być liczbą całkowitą.")



def require_secret_key():
    """Zwraca klucz sesji albo przerywa start aplikacji webowej. Sprawdzane
    tylko przez aplikacje Flask — monitor, watcher i CLI klucza nie potrzebują."""
    key = os.environ.get("SOC_SECRET_KEY", "")
    if len(key) < MIN_SECRET_LEN:
        raise RuntimeError(
            "SOC_SECRET_KEY nie jest ustawiony albo ma mniej niż "
            f"{MIN_SECRET_LEN} znaków. Wygeneruj klucz: "
            "python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return key


# Ciasteczko sesji tylko przez HTTPS. Za reverse proxy z TLS ustaw SOC_HTTPS=1.
# Lokalnie (http://localhost) musi zostać 0, inaczej przeglądarka nie wyśle ciasteczka.
SESSION_COOKIE_SECURE = os.environ.get("SOC_HTTPS", "0") == "1"

# Czas życia sesji (odświeżany przy każdym żądaniu, więc działa jak limit bezczynności).
SESSION_HOURS = _int("SOC_SESSION_HOURS", 8)

# Ile reverse proxy stoi przed aplikacją (docker-compose: 1 = Caddy). Dzięki temu
# request.remote_addr to prawdziwy adres klienta, a nie adres proxy — bez tego
# limit prób logowania i pole "ip" zdarzeń wpisywałyby zawsze adres Caddy.
# NIE ustawiaj wartości > 0, jeśli aplikacja jest wystawiona bez proxy: nagłówek
# X-Forwarded-For można wtedy sfałszować.
TRUSTED_PROXIES = _int("SOC_TRUSTED_PROXIES", 0)

# Formularz ręcznego wstrzykiwania zdarzeń (POST /) pozwala operatorowi wpisać
# dowolnego "użytkownika" — to narzędzie do demo i testowania reguł, a nie funkcja
# produkcyjna (fałszowanie logu). Domyślnie wyłączone.
DEMO_MODE = os.environ.get("SOC_DEMO_MODE", "0") == "1"

# Konta traktowane jako uprzywilejowane w regułach detekcji (porównanie bez
# względu na wielkość liter), rozdzielone przecinkami.
PRIVILEGED_ACTORS = {
    a.strip().lower()
    for a in os.environ.get("SOC_PRIVILEGED_ACTORS", "admin,root,administrator").split(",")
    if a.strip()
}

# Adres nasłuchu przy uruchomieniu "python bi_server.py" (tryb deweloperski).
# W kontenerze serwer startuje przez gunicorn (patrz Dockerfile).
HOST = os.environ.get("SOC_HOST", "127.0.0.1")

# Limity prób logowania (okno 15 min). Patrz auth.py.
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_FAILURES_PER_USER_IP = 5
LOGIN_MAX_FAILURES_PER_IP = 20
LOGIN_MAX_FAILURES_PER_USER = 30
APIKEY_MAX_FAILURES_PER_IP = 30
