"""
events.py — walidacja i normalizacja zdarzeń przed zapisem do bazy.

Wszystkie drogi wejścia (formularz, API z kluczem, import pliku, watcher
folderu) przechodzą przez te same funkcje, więc do bazy trafia tylko
zdarzenie o znanym kształcie. Wcześniej API zapisywało znacznik czasu
dokładnie tak, jak go dostało — jedno zdarzenie z `timestamp: "abc"`
wywracało pętlę detekcji (patrz tests/test_monitor.py).
"""

import datetime
import ipaddress
import re

MAX_TEXT = 80
MAX_RECORDS = 1_000_000_000
TS_FORMAT = "%Y-%m-%d %H:%M:%S"
MIN_YEAR = 2000
MAX_FUTURE = datetime.timedelta(days=1)

# Wartości oznaczające porażkę (logowania / operacji) w obcych systemach.
FAILURE_VALUES = {
    "failed", "fail", "failure", "error", "denied", "false", "0",
    "deny", "blocked", "401", "403", "404", "500",
}

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_EMPTY_WORDS = {"", "nan", "nat", "none", "null"}


class InvalidEvent(ValueError):
    """Zdarzenia nie da się zapisać (brak pola albo zły format)."""


def clean_text(value, field):
    if value is None:
        raise InvalidEvent(f"brak pola {field}")
    text = _CONTROL_CHARS.sub(" ", str(value)).strip()
    if text.lower() in _EMPTY_WORDS:
        raise InvalidEvent(f"puste pole {field}")
    return text[:MAX_TEXT]


def parse_timestamp(value, now=None):
    """Zwraca naiwny czas lokalny (jak reszta systemu). Akceptuje tekst w formacie
    ISO 8601 ("2026-11-25 08:00:00", "2026-11-25T08:00:00+01:00") oraz obiekty
    datetime. Liczby (epoch) i śmieci są odrzucane."""
    if isinstance(value, datetime.datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.datetime.fromisoformat(value.strip())
        except ValueError:
            raise InvalidEvent("zły format czasu")
    else:
        raise InvalidEvent("zły typ czasu")

    if dt != dt:  # pandas.NaT
        raise InvalidEvent("brak czasu")
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    dt = dt.replace(microsecond=0)

    now = now or datetime.datetime.now()
    if dt.year < MIN_YEAR or dt > now + MAX_FUTURE:
        raise InvalidEvent("czas poza dopuszczalnym zakresem")
    return dt


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return "0.0.0.0"  # nosec B104


def normalize_status(value):
    return "failed" if str(value).strip().lower() in FAILURE_VALUES else "success"


def normalize_records(value, default=1):
    try:
        number = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return default
    return max(0, min(number, MAX_RECORDS))


def normalize_event(actor, action, timestamp, ip=None, status="success", records=1, now=None):
    """Zwraca słownik gotowy do db.insert_events_bulk() albo rzuca InvalidEvent."""
    return {
        "actor": clean_text(actor, "actor"),
        "action": clean_text(action, "action"),
        "timestamp": parse_timestamp(timestamp, now).strftime(TS_FORMAT),
        "ip": normalize_ip(ip),
        "status": normalize_status(status),
        "records": normalize_records(records),
    }
