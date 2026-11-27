"""
generate_activity.py — generator syntetycznego ruchu + scenariuszy ataków,
teraz parametryzowany po tenant_id.

Zastosowanie praktyczne: podczas onboardingu nowego klienta / demo
sprzedażowego uruchamiasz to na chwilę dla jego tenanta, żeby dashboard
i pierwszy raport zgodności PDF miały czym się wypełnić, zanim podłączysz
realne logi z jego systemów.

Dane są w całości syntetyczne (adresy z zakresów prywatnych, użytkownicy user_001..).

Użycie:
    python generate_activity.py <tenant_id> [--count N] [--fast] [--seed S]
"""

import argparse
import datetime
import random
import sys
import time

import db

TENANT_ID = None
# Generator danych demo, nie kryptografia.
rng = random.Random()  # nosec B311

static_users = ["admin", "manager", "support", "guest", "finance_lead", "hr_admin", "it_ops"]
dynamic_users = [f"user_{i:03d}" for i in range(1, 101)]
users = static_users + dynamic_users

actions = ["login", "logout", "view_report", "export_data", "create_record",
           "update_record", "delete_record", "change_password", "access_dashboard"]


def random_ip_internal():
    return f"192.168.{rng.randint(1,5)}.{rng.randint(2,254)}"


def random_ip_external():
    return f"10.{rng.randint(200,254)}.{rng.randint(0,255)}.{rng.randint(2,254)}"


def random_ip_cloud():
    return f"172.31.{rng.randint(0,255)}.{rng.randint(2,254)}"


def random_timestamp():
    now = datetime.datetime.now()
    past = now - datetime.timedelta(hours=6)
    random_seconds = rng.randint(0, int((now - past).total_seconds()))
    ts = past + datetime.timedelta(seconds=random_seconds)
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def log_event(user, action, ts, ip, status="success", records=1):
    db.insert_event(TENANT_ID, user, action, ts, ip, status, records)
    print(f"[{status.upper():7}] {ts} {user:12} {action:15} ip={ip:16} records={records}")


def normal_event():
    user = rng.choice(users)
    action = rng.choice(actions)
    ip = random_ip_internal()
    ts = random_timestamp()
    status = "success"
    if action == "login" and rng.random() < 0.02:
        status = "failed"
    records = 1
    if action == "export_data":
        records = rng.randint(1, 200)
    elif action == "view_report":
        records = rng.randint(1, 10)
    log_event(user, action, ts, ip, status, records)


def scenario_credential_stuffing():
    attacker_ip = random_ip_external()
    compromised_user = rng.choice(dynamic_users)
    events = []
    n_attempts = rng.randint(15, 40)
    tried_users = rng.sample([u for u in users if u != compromised_user],
                                 min(n_attempts, len(users) - 1))
    for u in tried_users:
        events.append({"delay": rng.uniform(0.05, 0.25), "user": u, "action": "login",
                        "ip": attacker_ip, "status": "failed", "records": 0})
    events.append({"delay": rng.uniform(0.2, 0.6), "user": compromised_user, "action": "login",
                    "ip": attacker_ip, "status": "success", "records": 0})
    return compromised_user, attacker_ip, events


def scenario_silent_recon(compromised_user, attacker_ip):
    events = []
    n_phases = rng.randint(3, 5)
    interval = rng.uniform(6, 12)
    for phase in range(n_phases):
        n_events_this_phase = phase + 2
        for _ in range(n_events_this_phase):
            action = rng.choice(["view_report", "access_dashboard", "export_data"])
            records = rng.randint(1, 10) if action != "export_data" else rng.randint(5, 60)
            events.append({"delay": max(interval / n_events_this_phase, 0.3),
                            "user": compromised_user, "action": action, "ip": attacker_ip,
                            "status": "success", "records": records})
        interval *= 0.55
    return events


def scenario_mass_exfiltration(compromised_user, attacker_ip=None):
    ip = attacker_ip or random_ip_cloud()
    events = []
    n_chunks = rng.randint(3, 8)
    for _ in range(n_chunks):
        records = rng.randint(50_000, 500_000)
        events.append({"delay": rng.uniform(0.1, 0.4), "user": compromised_user,
                        "action": "export_data", "ip": ip, "status": "success", "records": records})
    return events


def scenario_full_attack_chain():
    compromised_user, attacker_ip, stuffing_events = scenario_credential_stuffing()
    recon_events = scenario_silent_recon(compromised_user, attacker_ip)
    exfil_events = scenario_mass_exfiltration(compromised_user, attacker_ip)
    return stuffing_events + recon_events + exfil_events


def scenario_insider_sabotage():
    night_hour = rng.randint(0, 4)
    ts = datetime.datetime.now().replace(
        hour=night_hour, minute=rng.randint(0, 59), second=rng.randint(0, 59)
    ).strftime("%Y-%m-%d %H:%M:%S")
    return [{"delay": 0, "user": "admin", "action": "delete_record", "ip": random_ip_internal(),
             "status": "success", "records": rng.randint(1, 5), "ts": ts}]


SCENARIOS = {
    "credential_stuffing": lambda: scenario_credential_stuffing()[2],
    "silent_recon": lambda: scenario_silent_recon(rng.choice(dynamic_users), random_ip_external()),
    "mass_exfiltration": lambda: scenario_mass_exfiltration(rng.choice(dynamic_users)),
    "insider_sabotage": scenario_insider_sabotage,
    "full_attack_chain": scenario_full_attack_chain,
}
SCENARIO_WEIGHTS = [3, 3, 2, 2, 1]
SCENARIO_PROBABILITY = 0.015

def main():
    global TENANT_ID, rng
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("tenant_id", type=int)
    parser.add_argument("--count", type=int, default=0, help="zakończ po N zdarzeniach (0 = bez końca)")
    parser.add_argument("--fast", action="store_true", help="bez opóźnień między zdarzeniami")
    parser.add_argument("--seed", type=int, default=None, help="ziarno generatora (powtarzalne dane)")
    args = parser.parse_args()
    TENANT_ID = args.tenant_id
    rng = random.Random(args.seed)  # nosec B311

    db.init_db()
    tenant = db.get_tenant(TENANT_ID)
    if not tenant:
        print(f"Brak tenanta o id={TENANT_ID}. Najpierw: python manage.py create-tenant \"Nazwa\" \"sektor\"")
        sys.exit(1)
    print(f"Generuję ruch demonstracyjny dla: {tenant['name']} (tenant_id={TENANT_ID})")

    sleep = (lambda _s: None) if args.fast else time.sleep
    produced = 0
    queue = []
    while not args.count or produced < args.count:
        try:
            if queue:
                delay, ev = queue.pop(0)
                sleep(delay)
                ts = ev.get("ts") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_event(ev["user"], ev["action"], ts, ev["ip"], ev["status"], ev["records"])
                produced += 1
            elif rng.random() < SCENARIO_PROBABILITY:
                name = rng.choices(list(SCENARIOS.keys()), weights=SCENARIO_WEIGHTS)[0]
                print(f"\n=== [SCENARIUSZ ATAKU] Symulacja: {name} ===\n")
                queue = [(e.get("delay", 0.5), e) for e in SCENARIOS[name]()]
            else:
                normal_event()
                produced += 1
                sleep(rng.uniform(0.05, 0.15))
        except KeyboardInterrupt:
            break
        except Exception as exc:  # noqa: BLE001
            print("generator error:", exc)
            sleep(1)


if __name__ == "__main__":
    main()
