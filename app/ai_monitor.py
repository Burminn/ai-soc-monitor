"""
ai_monitor.py — pętla detekcji anomalii, teraz wielodostępna (multi-tenant).

Kluczowa zmiana względem POC: modele ML, reguły heurystyczne i CAŁY stan
("znane IP użytkownika", "okno prób logowania" itd.) są utrzymywane
OSOBNO dla każdego tenanta (STATE[tenant_id]). To nie jest kosmetyka —
bez tego zachowanie jednego klienta wpływałoby na próg wykrywania
anomalii u innego klienta, co byłoby zarówno błędem produktowym, jak
i problemem kontraktowym (izolacja danych między klientami).

Dane wejściowe/wyjściowe: SQLite (db.py) zamiast logs.csv/alerts.csv.

Odporność (zmiany względem pierwszej wersji, każda ma test w tests/test_monitor.py):
  * kursor "ostatnie przetworzone zdarzenie" jest liczony po id zdarzenia tenanta
    (wcześniej porównywano globalne id z liczbą zdarzeń tenanta, więc drugi i kolejni
    klienci przestawali być analizowani po pierwszej partii),
  * kursor jest zapisywany w bazie — restart nie dubluje alertów,
  * reguły działają od pierwszego zdarzenia, modele ML dopiero po MIN_TRAIN zdarzeniach,
  * błąd w danych jednego klienta nie zatrzymuje pozostałych (osobny try/except na tenanta,
    a partia, która wywala się trzy razy z rzędu, jest pomijana z wpisem w logu).
"""

import logging
import time
from collections import defaultdict, deque

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import LabelEncoder, StandardScaler

import config
import db

log = logging.getLogger("soc.monitor")

MAX_CONSECUTIVE_FAILURES = 3
MIN_TRAIN = 30
RETRAIN_SECONDS = 60
TRAIN_WINDOW_EVENTS = 5000  # ile ostatnich zdarzeń bierzemy pod trening modeli

BRUTEFORCE_FAILED_THRESHOLD = 8
BRUTEFORCE_WINDOW_SECONDS = 120

VOLUME_SPIKE_RECORDS = 5000
VOLUME_SPIKE_BURST_COUNT = 3
VOLUME_SPIKE_WINDOW_SECONDS = 300

RECON_TREND_MIN_PHASES = 3
RECON_TREND_WINDOW_MINUTES = 10

RULE_WEIGHTS = {
    "RULE_BRUTEFORCE": 4,
    "RULE_VOLUME_SPIKE": 4,
    "RULE_RECON_TREND": 3,
    "RULE_NIGHT_PRIVILEGED": 2,
    "RULE_NEW_IP": 1,
}

TENANT_POLL_SECONDS = 1


def new_tenant_state():
    return {
        "trained": False,
        "models": {},
        "last_train": 0,
        "seen_id": 0,
        "loaded": False,
        "failures": 0,
        "pending_end": 0,
        "le_action": LabelEncoder(),
        "user_known_ips": defaultdict(set),
        "ip_failed_logins": defaultdict(deque),
        "user_volume_events": defaultdict(deque),
        "user_recon_windows": defaultdict(deque),
    }


STATE = defaultdict(new_tenant_state)


def events_to_df(events):
    return pd.DataFrame(events, columns=["id", "tenant_id", "actor", "action",
                                          "timestamp", "ip", "status", "records", "created_at"])


def featurize(df, state):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["hour"] = df["timestamp"].dt.hour.fillna(12).astype(int)
    df["weekday"] = df["timestamp"].dt.weekday.fillna(0).astype(int)
    df["action"] = df["action"].fillna("unknown").astype(str)
    df["status"] = df["status"].fillna("success").astype(str)
    df["ip"] = df["ip"].fillna("0.0.0.0").astype(str)
    df["is_failed"] = (df["status"] == "failed").astype(int)
    df["records"] = pd.to_numeric(df["records"], errors="coerce").fillna(0)
    df["records_log"] = np.log1p(df["records"])

    le = state["le_action"]
    if not hasattr(le, "classes_"):
        le.fit(df["action"])
    new_actions = set(df["action"]) - set(le.classes_)
    if new_actions:
        le.fit(list(le.classes_) + list(new_actions))
    df["action_code"] = le.transform(df["action"])

    df["actor_hour"] = df["actor"].astype(str) + "|" + df["timestamp"].dt.strftime("%Y-%m-%d %H")
    counts = df.groupby("actor_hour").size().to_dict()
    df["actor_activity_count"] = df["actor_hour"].map(counts).fillna(1)

    features = df[["hour", "weekday", "action_code", "actor_activity_count",
                    "records_log", "is_failed"]].astype(float)
    return df, features


def train_models(df, state):
    if len(df) < MIN_TRAIN:
        return False
    df_feat, X = featurize(df, state)

    values = X.values
    iso = IsolationForest(contamination=0.06, random_state=42)
    iso.fit(values)
    lof = LocalOutlierFactor(n_neighbors=min(20, len(values) - 1), contamination=0.06, novelty=True)
    lof.fit(values)
    scaler = StandardScaler()
    scaler.fit(values)

    state["models"] = {"iso": iso, "lof": lof, "scaler": scaler}
    state["trained"] = True
    state["last_train"] = time.time()
    return True


# ------------------------------------------------------------- reguły ------

def check_new_ip(state, actor, ip, action):
    known = state["user_known_ips"][actor]
    is_new = bool(known) and ip not in known and action == "login"
    known.add(ip)
    return is_new


def check_bruteforce(state, ip, ts, status):
    dq = state["ip_failed_logins"][ip]
    if status == "failed":
        dq.append(ts)
    while dq and (ts - dq[0]).total_seconds() > BRUTEFORCE_WINDOW_SECONDS:
        dq.popleft()
    return len(dq) >= BRUTEFORCE_FAILED_THRESHOLD


def check_volume_spike(state, actor, ts, records, action):
    dq = state["user_volume_events"][actor]
    if action == "export_data" and records >= VOLUME_SPIKE_RECORDS:
        dq.append(ts)
    while dq and (ts - dq[0]).total_seconds() > VOLUME_SPIKE_WINDOW_SECONDS:
        dq.popleft()
    return len(dq) >= VOLUME_SPIKE_BURST_COUNT


def check_recon_trend(state, actor, ts, action):
    if action not in ("view_report", "access_dashboard", "export_data"):
        return False
    dq = state["user_recon_windows"][actor]
    minute_bucket = (ts.minute // RECON_TREND_WINDOW_MINUTES) * RECON_TREND_WINDOW_MINUTES
    window_key = ts.replace(minute=minute_bucket, second=0, microsecond=0)

    if dq and dq[-1][0] == window_key:
        dq[-1] = (window_key, dq[-1][1] + 1)
    else:
        dq.append([window_key, 1])
    while len(dq) > RECON_TREND_MIN_PHASES + 2:
        dq.popleft()
    if len(dq) < RECON_TREND_MIN_PHASES:
        return False
    recent = [c for _, c in list(dq)[-RECON_TREND_MIN_PHASES:]]
    is_increasing = all(recent[i] < recent[i + 1] for i in range(len(recent) - 1))
    return is_increasing and recent[-1] >= 3


def apply_rules(state, row):
    ts = row.timestamp
    detected = []
    if check_new_ip(state, row.actor, row.ip, row.action):
        detected.append("RULE_NEW_IP")
    if check_bruteforce(state, row.ip, ts, row.status):
        detected.append("RULE_BRUTEFORCE")
    if check_volume_spike(state, row.actor, ts, row.records, row.action):
        detected.append("RULE_VOLUME_SPIKE")
    if check_recon_trend(state, row.actor, ts, row.action):
        detected.append("RULE_RECON_TREND")
    if (row.actor.lower() in config.PRIVILEGED_ACTORS and 0 <= row.hour <= 5
            and row.action in ("delete_record", "export_data")):
        detected.append("RULE_NIGHT_PRIVILEGED")
    return detected


def classify_attack_type(detectors):
    d = set(detectors)
    labels = []
    if "RULE_BRUTEFORCE" in d:
        labels.append("Możliwy atak siłowy / credential stuffing")
    if "RULE_VOLUME_SPIKE" in d:
        labels.append("Podejrzana masowa eksfiltracja danych")
    if "RULE_RECON_TREND" in d:
        labels.append("Możliwy cichy rekonesans konta")
    if "RULE_NIGHT_PRIVILEGED" in d:
        labels.append("Nietypowa aktywność uprzywilejowanego konta w nocy")
    if "RULE_NEW_IP" in d and not labels:
        labels.append("Logowanie z nieznanego wcześniej adresu IP")
    if not labels and d & {"IsolationForest", "LOF", "DBSCAN"}:
        labels.append("Anomalia behawioralna (wykryta przez modele ML)")
    return " + ".join(labels) if labels else "Nieokreślona anomalia"


def calculate_score(votes, detectors, actor, ts, action):
    score = votes * 2
    risky_actions = {"delete_record": 3, "export_data": 2, "change_password": 1}
    score += risky_actions.get(action, 0)
    if actor.lower() in config.PRIVILEGED_ACTORS:
        score += 2
    if 0 <= ts.hour <= 5:
        score += 1
    for d in detectors:
        score += RULE_WEIGHTS.get(d, 0)
    return min(score, 15)


def severity_from_score(score):
    if score <= 2: return "LOW"
    if score <= 5: return "MEDIUM"
    if score <= 9: return "HIGH"
    return "CRITICAL"


# ------------------------------------------------------------ per tenant ---

def _load_state(tenant_id, state):
    """Po restarcie: wznawia od zapisanego kursora i odtwarza znane adresy IP.
    Okna czasowe reguł (brute force, eksport, rekonesans — do 10 minut) nie są
    odtwarzane, więc zdarzenia tuż przed restartem mogą nie złożyć się w alert."""
    state["seen_id"] = db.get_monitor_cursor(tenant_id)
    if state["seen_id"]:
        for actor, ip in db.known_actor_ips(tenant_id, state["seen_id"]):
            state["user_known_ips"][actor].add(ip)
    state["loaded"] = True


def _detect(tenant_id, state, new_events):
    df_new, X_new = featurize(events_to_df(new_events), state)

    # zdarzenia bez czytelnego czasu (np. zapisane starszą wersją) pomijamy
    valid = df_new["timestamp"].notna()
    df_new, X_new = df_new[valid], X_new[valid]
    if df_new.empty:
        return

    # reguły okienkowe wymagają kolejności czasowej (import pliku bywa nieposortowany)
    order = df_new["timestamp"].argsort(kind="stable").to_numpy()
    df_new, X_new = df_new.iloc[order], X_new.iloc[order]

    n = len(df_new)
    no_signal = [1] * n
    iso_preds = lof_preds = db_preds = no_signal
    if state["trained"]:
        iso, lof, scaler = state["models"]["iso"], state["models"]["lof"], state["models"]["scaler"]
        values = X_new.values
        iso_preds = iso.predict(values)
        lof_preds = lof.predict(values)
        db_preds = DBSCAN(eps=1.5, min_samples=min(5, n)).fit_predict(scaler.transform(values))

    for i, row in enumerate(df_new.itertuples()):
        detected = []
        if iso_preds[i] == -1: detected.append("IsolationForest")
        if lof_preds[i] == -1: detected.append("LOF")
        if db_preds[i] == -1: detected.append("DBSCAN")
        detected += apply_rules(state, row)

        if detected:
            votes = len(detected)
            attack_type = classify_attack_type(detected)
            score = calculate_score(votes, detected, row.actor, row.timestamp, row.action)
            severity = severity_from_score(score)

            db.insert_alert(
                tenant_id, row.actor, row.action,
                row.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "|".join(detected), votes, attack_type,
                int(row.records), score, severity,
            )
            log.info("[tenant %s] ALERT: %s %s %s %s -> %s (%s)", tenant_id, row.actor,
                     row.action, row.timestamp, "|".join(detected), attack_type, severity)


def process_tenant(tenant_id):
    state = STATE[tenant_id]
    if not state["loaded"]:
        _load_state(tenant_id, state)

    if db.max_event_id(tenant_id) <= state["seen_id"]:
        return

    total = db.count_events(tenant_id)
    if (time.time() - state["last_train"] > RETRAIN_SECONDS) or (not state["trained"] and total >= MIN_TRAIN):
        recent = db.fetch_recent_events(tenant_id, TRAIN_WINDOW_EVENTS)
        if recent:
            train_models(events_to_df(recent), state)

    new_events = db.fetch_events_since(tenant_id, state["seen_id"])
    if not new_events:
        return
    state["pending_end"] = new_events[-1]["id"]
    _detect(tenant_id, state, new_events)

    state["seen_id"] = state["pending_end"]
    db.set_monitor_cursor(tenant_id, state["seen_id"])


def run_once():
    """Jedna iteracja po wszystkich tenantach. Błąd jednego tenanta nie wpływa na pozostałych."""
    for tenant in db.list_tenants():
        tenant_id = tenant["id"]
        state = STATE[tenant_id]
        try:
            process_tenant(tenant_id)
            state["failures"] = 0
        except Exception:  # noqa: BLE001 - pętla monitora ma przetrwać każdy błąd danych
            state["failures"] += 1
            log.exception("błąd przetwarzania tenanta %s (próba %s z %s)",
                          tenant_id, state["failures"], MAX_CONSECUTIVE_FAILURES)
            if state["failures"] >= MAX_CONSECUTIVE_FAILURES and state["pending_end"] > state["seen_id"]:
                log.error("[tenant %s] pomijam partię zdarzeń do id=%s po %s nieudanych próbach",
                          tenant_id, state["pending_end"], state["failures"])
                state["seen_id"] = state["pending_end"]
                db.set_monitor_cursor(tenant_id, state["seen_id"])
                state["failures"] = 0


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db.init_db()
    log.info("AI monitor (multi-tenant) uruchomiony.")
    while True:
        run_once()
        time.sleep(TENANT_POLL_SECONDS)


if __name__ == "__main__":
    main()
