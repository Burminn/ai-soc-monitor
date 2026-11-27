"""
ingest.py — automatyczne rozpoznawanie struktury CUDZEGO pliku (CSV/JSON
eksportowanego z systemu klienta) i mapowanie go na schemat zdarzeń
(actor, action, timestamp, ip, status, records).

WAŻNE uczciwe zastrzeżenie: to NIE jest model AI, który "rozumie" dane —
to zestaw deterministycznych, wytłumaczalnych heurystyk (parsowanie dat,
dopasowanie do wzorca IP, słowniki słów kluczowych, nazwy kolumn).
Dzięki temu działanie jest przewidywalne i można pokazać klientowi/
audytorowi DLACZEGO kolumna X została uznana za "użytkownika" — czego
nie dałoby się łatwo wytłumaczyć przy czarnej skrzynce ML.

Każde mapowanie ma liczbę ufności. Poniżej progu system NIE importuje
automatycznie — zwraca propozycję do potwierdzenia przez człowieka.
To świadomy wybór: lepiej raz poprosić operatora o kliknięcie "zatwierdź",
niż cicho zaimportować dane źle zmapowane i mieć błędne alerty.
"""

import io
import ipaddress
import json
import os
import re
import warnings

import numpy as np
import pandas as pd

import events

MAX_ROWS = 200_000  # górny limit wierszy z jednego pliku (ochrona pamięci)
ROLES = ("timestamp", "actor", "action", "ip", "status", "records")
REQUIRED_ROLES = ("timestamp", "actor", "action")

IDENT_RE = re.compile(r"^[\w.\-@+]{2,80}$")

STATUS_VALUES = {
    "success", "ok", "succeeded", "failed", "fail", "failure", "error",
    "denied", "true", "false", "200", "201", "204", "401", "403", "404",
    "500", "0", "1", "allow", "allowed", "deny", "blocked", "granted",
}
ACTION_KEYWORDS = [
    "login", "logon", "logout", "signin", "signout", "create", "insert",
    "update", "modify", "delete", "remove", "export", "download", "upload",
    "view", "read", "access", "report", "change", "reset", "grant", "revoke",
]

NAME_HINTS = {
    "timestamp": ["time", "date", "timestamp", "czas", "data", "occurred", "created_at"],
    "actor": ["user", "login", "account", "email", "operator", "actor", "employee",
              "pracownik", "uzytkownik", "użytkownik", "osoba", "performed_by"],
    "action": ["action", "event", "operation", "activity", "akcja", "zdarzenie",
               "czynnosc", "czynność", "typ"],
    "ip": ["ip", "address", "adres", "src_ip", "source_ip", "host"],
    "status": ["status", "result", "outcome", "wynik", "rezultat", "code"],
    "records": ["records", "count", "rows", "bytes", "size", "ilosc", "ilość",
                "liczba", "volume", "qty", "quantity"],
}

ROLE_PRIORITY = ["timestamp", "actor", "action", "status", "ip", "records"]

# Poniżej tej wartości mapowanie danej roli jest traktowane jako "niepewne"
CONFIDENCE_THRESHOLD = 0.9


def _name_bonus(col_name, role):
    name = str(col_name).lower()
    return 0.8 if any(h in name for h in NAME_HINTS[role]) else 0.0


def _sample(series, n=300):
    return series.dropna().astype(str).head(n)


def _score_timestamp(series, col_name):
    s = _sample(series)
    if len(s) == 0:
        return 0.0
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        parsed = pd.to_datetime(s, errors="coerce")
    rate = parsed.notna().mean()
    return rate * 2.0 + _name_bonus(col_name, "timestamp")


def _is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _score_ip(series, col_name):
    s = _sample(series)
    if len(s) == 0:
        return 0.0
    rate = s.apply(_is_ip).mean()
    return rate * 2.0 + _name_bonus(col_name, "ip")


def _score_status(series, col_name):
    s = _sample(series).str.lower()
    if len(s) == 0:
        return 0.0
    rate = s.isin(STATUS_VALUES).mean()
    cardinality = series.nunique(dropna=True) / max(len(series), 1)
    low_card_bonus = 0.5 if cardinality < 0.05 else 0.0
    return rate * 2.0 + low_card_bonus + _name_bonus(col_name, "status")


def _score_action(series, col_name):
    s = _sample(series).str.lower()
    if len(s) == 0:
        return 0.0
    rate = s.apply(lambda v: any(k in v for k in ACTION_KEYWORDS)).mean()
    cardinality = series.nunique(dropna=True) / max(len(series), 1)
    low_card_bonus = 0.5 if cardinality < 0.2 else 0.0
    return rate * 2.0 + low_card_bonus + _name_bonus(col_name, "action")


def _score_records(series, col_name):
    numeric = pd.to_numeric(series, errors="coerce")
    rate = numeric.notna().mean()
    if rate < 0.8:
        return 0.0
    return rate * 1.2 + _name_bonus(col_name, "records")


def _score_actor(series, col_name):
    s = _sample(series)
    if len(s) == 0:
        return 0.0
    ident_rate = s.apply(lambda v: bool(IDENT_RE.match(v))).mean()
    cardinality = series.nunique(dropna=True) / max(len(series), 1)
    mid_card_bonus = 0.6 if 0.02 < cardinality < 0.9 else 0.0
    return ident_rate * 1.0 + mid_card_bonus + _name_bonus(col_name, "actor")


SCORERS = {
    "timestamp": _score_timestamp,
    "actor": _score_actor,
    "action": _score_action,
    "ip": _score_ip,
    "status": _score_status,
    "records": _score_records,
}


def autodetect_mapping(df):
    """
    Zwraca:
      {
        "mapping": {"timestamp": "kolumna_A", "actor": "kolumna_C", ...},
        "confidence": {"timestamp": 1.8, ...},
        "unmapped_columns": [...],
        "auto_importable": bool,   # czy pewność wystarcza, by importować bez potwierdzenia
        "warnings": [...],
      }

    Użyty jest algorytm węgierski (optymalne dopasowanie globalne roli<->kolumna
    po sumarycznym wyniku), a nie zachłanne przypisywanie rola-po-roli.
    Zachłanne podejście potrafiło "zabrać" dobrą kolumnę pod gorzej pasującą
    rolę tylko dlatego, że ta rola była rozpatrywana wcześniej w kolejności —
    np. kolumna ze statusami "ok"/"ok" mogła zostać błędnie uznana za
    identyfikator użytkownika, zanim doszło do oceny roli "status".
    """
    from scipy.optimize import linear_sum_assignment

    cols = list(df.columns)
    roles = ROLE_PRIORITY

    score_matrix = np.zeros((len(roles), len(cols)))
    for i, role in enumerate(roles):
        for j, col in enumerate(cols):
            try:
                score_matrix[i, j] = SCORERS[role](df[col], col)
            except Exception:
                score_matrix[i, j] = 0.0

    row_idx, col_idx = linear_sum_assignment(-score_matrix)  # maksymalizacja sumy

    mapping, confidence, used = {}, {}, set()
    for r, c in zip(row_idx, col_idx):
        score = score_matrix[r, c]
        if score > 0:
            mapping[roles[r]] = cols[c]
            confidence[roles[r]] = round(float(score), 2)
            used.add(cols[c])

    warnings_list = []
    required = ["timestamp", "actor", "action"]
    missing_required = [r for r in required if r not in mapping]
    if missing_required:
        warnings_list.append(
            f"Nie udało się jednoznacznie rozpoznać kolumn dla: {', '.join(missing_required)}. "
            "Wskaż je ręcznie przed importem."
        )

    low_confidence = [r for r in mapping if confidence.get(r, 0) < CONFIDENCE_THRESHOLD]
    if low_confidence:
        warnings_list.append(
            f"Niska pewność mapowania dla: {', '.join(low_confidence)}. Zweryfikuj przed importem."
        )

    auto_importable = not missing_required and not low_confidence

    return {
        "mapping": mapping,
        "confidence": confidence,
        "unmapped_columns": [c for c in cols if c not in used],
        "auto_importable": auto_importable,
        "warnings": warnings_list,
    }


def validate_mapping(df, mapping):
    """Sprawdza mapowanie przysłane przez klienta. Zwraca listę błędów (pusta = OK).
    Mapowanie pochodzi z przeglądarki, więc nie wolno mu ufać: nieznana rola albo
    nieistniejąca kolumna dawały wcześniej błąd 500."""
    if not isinstance(mapping, dict):
        return ["Mapowanie musi być obiektem {rola: kolumna}."]
    errors = []
    for role, col in mapping.items():
        if role not in ROLES:
            errors.append(f"Nieznana rola: {str(role)[:40]}.")
        elif not isinstance(col, str) or col not in df.columns:
            errors.append(f"Plik nie ma kolumny wskazanej dla roli {role}.")
    missing = [r for r in REQUIRED_ROLES if r not in mapping]
    if missing:
        errors.append(f"Mapowanie musi zawierać: {', '.join(REQUIRED_ROLES)}.")
    return errors


def _to_datetimes(series):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return pd.to_datetime(series, errors="coerce")
        except (ValueError, TypeError):
            return series.apply(lambda v: pd.to_datetime(v, errors="coerce"))


def apply_mapping(df, mapping, defaults=None):
    """
    Zamienia surowy DataFrame na znormalizowane wiersze gotowe do
    db.insert_events_bulk(). Każdy wiersz przechodzi przez events.normalize_event
    (ta sama walidacja co formularz i API). Brakujące role wypełniane są z
    `defaults`. Wiersze z niepoprawną datą albo pustym użytkownikiem/akcją są
    odrzucane i zliczane osobno.

    Zakłada, że `mapping` przeszło validate_mapping().
    """
    defaults = defaults or {}
    columns = {}
    for role, col in mapping.items():
        if role == "timestamp":
            columns[role] = _to_datetimes(df[col]).tolist()
        else:
            columns[role] = df[col].tolist()

    def value(role, i, default=None):
        return columns[role][i] if role in columns else defaults.get(role, default)

    rows, rejected = [], 0
    for i in range(len(df)):
        try:
            rows.append(events.normalize_event(
                actor=value("actor", i, "unknown"),
                action=value("action", i, "unknown"),
                timestamp=value("timestamp", i),
                ip=value("ip", i, "0.0.0.0"),  # nosec B104
                status=value("status", i, "success"),
                records=value("records", i, 1),
            ))
        except events.InvalidEvent:
            rejected += 1
    return rows, rejected


def _decode(raw):
    for encoding in ("utf-8-sig", "cp1250"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def load_dataframe(file_storage_or_path, filename_hint=""):
    """Wczytuje CSV lub JSON (lista obiektów / obiekt z listą pod dowolnym kluczem
    najwyżej 1 poziom głęboko) do pandas.DataFrame. Rozpoznaje separator CSV oraz
    kodowanie (UTF-8, w razie czego Windows-1250 — typowe dla polskich eksportów)."""
    name = (filename_hint or getattr(file_storage_or_path, "filename", "")).lower()

    if hasattr(file_storage_or_path, "read"):
        raw = file_storage_or_path.read()
    else:
        safe_root = os.path.realpath(os.path.join(os.path.dirname(__file__), "imports"))
        requested = os.fspath(file_storage_or_path)
        if not requested:
            raise ValueError("Brak ścieżki pliku.")
        if os.path.isabs(requested):
            raise ValueError("Niedozwolona ścieżka pliku.")
        normalized_requested = os.path.normpath(requested)
        if normalized_requested == ".." or normalized_requested.startswith(".." + os.sep):
            raise ValueError("Niedozwolona ścieżka pliku.")

        full_path = os.path.realpath(os.path.join(safe_root, normalized_requested))
        try:
            if os.path.commonpath([safe_root, full_path]) != safe_root:
                raise ValueError("Niedozwolona ścieżka pliku.")
        except ValueError as exc:
            raise ValueError("Niedozwolona ścieżka pliku.") from exc

        with open(full_path, "rb") as fh:
            raw = fh.read()
    text = _decode(raw)

    if name.endswith(".json"):
        data = json.loads(text)
        if isinstance(data, dict):
            list_fields = [v for v in data.values() if isinstance(v, list)]
            data = list_fields[0] if list_fields else [data]
        df = pd.json_normalize(data)
    else:
        df = pd.read_csv(io.StringIO(text), sep=None, engine="python")

    if len(df) > MAX_ROWS:
        raise ValueError(f"Plik ma za dużo wierszy (limit {MAX_ROWS}).")
    df.columns = [str(c) for c in df.columns]
    return df
