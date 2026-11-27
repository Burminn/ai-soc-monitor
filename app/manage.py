"""
manage.py — CLI do onboardingu klienta (tenanta) i operatorów.

Użycie:
    python manage.py init-db
    python manage.py create-tenant "Nazwa firmy" "sektor"      # wypisuje klucz API (raz!)
    python manage.py create-user 1 jan.kowalski                 # hasło pobierane interaktywnie
    python manage.py rotate-api-key 1                           # nowy klucz API (stary przestaje działać)
    python manage.py list-tenants

Hasło nie jest przyjmowane jako argument wiersza poleceń (trafiałoby do historii
powłoki i listy procesów). Do automatyzacji: zmienna SOC_NEW_PASSWORD.
"""

import argparse
import getpass
import os
import sys

import db


def _password():
    env = os.environ.get("SOC_NEW_PASSWORD")
    if env:
        return env
    first = getpass.getpass("Hasło (min. %d znaków): " % db.MIN_PASSWORD_LEN)
    if first != getpass.getpass("Powtórz hasło: "):
        raise ValueError("Hasła nie są identyczne.")
    return first


def build_parser():
    p = argparse.ArgumentParser(description="Zarządzanie tenantami i użytkownikami AI SOC Monitor.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    t = sub.add_parser("create-tenant")
    t.add_argument("name")
    t.add_argument("sector", nargs="?")
    u = sub.add_parser("create-user")
    u.add_argument("tenant_id", type=int)
    u.add_argument("username")
    u.add_argument("role", nargs="?", default="operator")
    r = sub.add_parser("rotate-api-key")
    r.add_argument("tenant_id", type=int)
    sub.add_parser("list-tenants")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "init-db":
            db.init_db()
            print(f"Baza zainicjalizowana: {db.DB_PATH}")
        elif args.cmd == "create-tenant":
            db.init_db()
            tenant_id = db.create_tenant(args.name, args.sector)
            api_key = db.rotate_api_key(tenant_id)
            print(f"Utworzono tenanta id={tenant_id} name={args.name!r}")
            print(f"Klucz API (widoczny tylko teraz, w bazie jest sam skrót): {api_key}")
        elif args.cmd == "create-user":
            db.init_db()
            db.create_user(args.tenant_id, args.username, _password(), args.role)
            print(f"Utworzono użytkownika {args.username!r} dla tenanta {args.tenant_id}")
        elif args.cmd == "rotate-api-key":
            db.init_db()
            db.rotate_api_key(args.tenant_id)
            print("Nowy klucz API wygenerowany.")
        elif args.cmd == "list-tenants":
            db.init_db()
            for t in db.list_tenants():
                print(f"[{t['id']}] {t['name']} — sektor: {t['sector']} (od {t['created_at']})")
    except ValueError as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
