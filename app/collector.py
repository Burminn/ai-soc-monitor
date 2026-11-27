"""
collector.py — cykliczne skanowanie katalogu w poszukiwaniu nowych plików
CSV/JSON i automatyczny import przez silnik z ingest.py.

Zastosowanie: klient nie ma API, ale jego system potrafi codziennie
wyeksportować CSV (np. przez zaplanowane zadanie / SFTP do wskazanego
folderu). collector.py pilnuje tego folderu i sam wciąga nowe pliki —
BEZ udziału człowieka, ale tylko wtedy, gdy auto-detekcja ma wysoką
pewność. W przeciwnym razie plik trafia do podfolderu needs_review/,
żeby operator zaimportował go ręcznie przez /ingest w dashboardzie
(tam może poprawić mapowanie zanim zatwierdzi).

Struktura katalogu nadzorowanego (per tenant):
  <drop_dir>/incoming/       <- tu klient/cron wrzuca pliki
  <drop_dir>/processed/      <- pliki poprawnie zaimportowane (archiwum)
  <drop_dir>/needs_review/   <- pliki o niepewnym mapowaniu — do ręcznej weryfikacji
  <drop_dir>/failed/         <- pliki, których w ogóle nie dało się wczytać

Użycie:
    python collector.py <tenant_id> <drop_dir> [--interval 30]
"""

import sys
import os
import time
import shutil
import argparse
import datetime

import db
import ingest

SUPPORTED_EXT = (".csv", ".json")


def ensure_dirs(drop_dir):
    for sub in ("incoming", "processed", "needs_review", "failed"):
        os.makedirs(os.path.join(drop_dir, sub), exist_ok=True)


def process_file(tenant_id, path, drop_dir):
    filename = os.path.basename(path)
    try:
        df = ingest.load_dataframe(path, filename_hint=filename)
    except Exception as e:
        print(f"[BŁĄD WCZYTANIA] {filename}: {e}")
        shutil.move(path, os.path.join(drop_dir, "failed", filename))
        return

    if df.empty:
        print(f"[PUSTY PLIK] {filename} — pomijam")
        shutil.move(path, os.path.join(drop_dir, "failed", filename))
        return

    result = ingest.autodetect_mapping(df)

    if not result["auto_importable"]:
        print(f"[NISKA PEWNOŚĆ] {filename} — {'; '.join(result['warnings'])} "
              f"-> przenoszę do needs_review/ (import ręczny przez dashboard)")
        dest = os.path.join(drop_dir, "needs_review", filename)
        shutil.move(path, dest)
        # Zostawiamy obok plik .mapping.txt z tym, co system i tak rozpoznał —
        # operator wykonujący ręczny import w /ingest ma punkt startowy.
        with open(dest + ".mapping_proposal.txt", "w", encoding="utf-8") as f:
            f.write(f"Propozycja mapowania (niepotwierdzona):\n{result['mapping']}\n\n"
                    f"Pewność:\n{result['confidence']}\n\n"
                    f"Ostrzeżenia:\n{result['warnings']}\n")
        return

    rows, rejected = ingest.apply_mapping(df, result["mapping"])
    inserted = db.insert_events_bulk(tenant_id, rows)

    print(f"[OK] {filename}: zaimportowano {inserted}, odrzucono {rejected} "
          f"(mapowanie: {result['mapping']})")
    shutil.move(path, os.path.join(drop_dir, "processed", filename))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tenant_id", type=int)
    parser.add_argument("drop_dir")
    parser.add_argument("--interval", type=int, default=30, help="sekundy między skanami")
    args = parser.parse_args()

    tenant = db.get_tenant(args.tenant_id)
    if not tenant:
        print(f"Brak tenanta o id={args.tenant_id}")
        sys.exit(1)

    ensure_dirs(args.drop_dir)
    incoming = os.path.join(args.drop_dir, "incoming")

    print(f"Watcher uruchomiony dla: {tenant['name']} (tenant_id={args.tenant_id})")
    print(f"Obserwuję: {incoming} (co {args.interval}s)")

    while True:
        try:
            for name in sorted(os.listdir(incoming)):
                if not name.lower().endswith(SUPPORTED_EXT):
                    continue
                path = os.path.join(incoming, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue  # dowiązania symboliczne mogłyby wskazywać poza folder
                # plik może być jeszcze w trakcie kopiowania (np. przez SFTP) —
                # prosty heurystyczny "debounce": sprawdź, czy rozmiar jest stabilny
                size1 = os.path.getsize(path)
                time.sleep(1)
                if not os.path.exists(path) or os.path.getsize(path) != size1:
                    continue
                process_file(args.tenant_id, path, args.drop_dir)
        except Exception as e:
            print("collector error:", e)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
