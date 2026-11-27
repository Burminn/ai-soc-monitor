# Detection notes

| Detector | Trigger (defaults in `ai_monitor.py`) | Label shown | Indicative ATT&CK |
|---|---|---|---|
| RULE_BRUTEFORCE | ≥ 8 failed logins from one IP within 120 s | possible brute force / credential stuffing | T1110 (Credential Access) |
| RULE_VOLUME_SPIKE | ≥ 3 `export_data` with ≥ 5000 records within 300 s by one actor | suspicious mass exfiltration | TA0010 Exfiltration |
| RULE_RECON_TREND | read-type actions rising in 3 consecutive 10-minute windows (last ≥ 3) | possible quiet account recon | TA0007 Discovery |
| RULE_NIGHT_PRIVILEGED | privileged account (`SOC_PRIVILEGED_ACTORS`) deleting/exporting 00:00–05:59 | unusual privileged activity at night | T1078 (Valid Accounts) |
| RULE_NEW_IP | `login` from an IP not seen before for that actor | login from a new IP | T1078 |
| IsolationForest / LOF | trained on the last 5000 events per tenant (min. 30), retrained every 60 s | behavioural anomaly | — |
| DBSCAN | run on the current micro-batch only | behavioural anomaly | — |

The ATT&CK column is an **indicative** mapping to help reading alerts, not a validated detection-engineering mapping.

Score = 2 × model votes + action risk (delete 3, export 2, change_password 1) + 2 for privileged actors
+ 1 for 00:00–05:59 + rule weights, capped at 15. Severity: ≤2 LOW, ≤5 MEDIUM, ≤9 HIGH, else CRITICAL.

Limitations of the ML part are listed in the README. Nothing here has been evaluated on labelled real-world data.
