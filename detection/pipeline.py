"""Run detections + anomaly layer, score them honestly, and write artifacts."""
from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd

from . import generate_logs
from . import rules as R
from .anomaly import score as anomaly_score
from .triage import build_queue

TECHNIQUE_NAME = {"T1110": "Brute Force", "T1078": "Valid Accounts (Impossible Travel)",
                  "T1059": "Command and Scripting", "T1548": "Privilege Escalation",
                  "T1041": "Exfiltration"}


def evaluate(df, alerts):
    mal = df["is_malicious"] == 1
    idx_to_attack = df.loc[mal, "attack_id"].to_dict()
    all_cases = set(df.loc[mal, "attack_id"].dropna().unique())

    tp = fp = 0
    detected = set()
    alert_rows = []
    for a in alerts:
        matched = {idx_to_attack[i] for i in a["event_idx"] if i in idx_to_attack}
        is_tp = len(matched) > 0
        tp += is_tp
        fp += (not is_tp)
        detected |= matched
        alert_rows.append({**{k: a[k] for k in ("rule", "technique", "severity", "entity", "detail")},
                           "outcome": "true_positive" if is_tp else "false_positive"})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = len(detected) / len(all_cases) if all_cases else 0.0

    per_tech = []
    for t in sorted(all_cases_by_tech(df)):
        cases_t = cases_for_tech(df, t)
        det_t = len(cases_t & detected)
        per_tech.append({"technique": t, "name": TECHNIQUE_NAME.get(t, t),
                         "cases": len(cases_t), "detected": det_t,
                         "recall": round(det_t / len(cases_t), 2) if cases_t else 0.0})
    return {"alerts_total": len(alerts), "true_positives": tp, "false_positives": fp,
            "precision": round(precision, 3), "case_recall": round(recall, 3),
            "cases_total": len(all_cases), "cases_detected": len(detected)}, \
           pd.DataFrame(alert_rows), per_tech, detected, all_cases


def all_cases_by_tech(df):
    m = df[df.is_malicious == 1]
    return set(m["technique"].dropna().unique())


def cases_for_tech(df, t):
    m = df[(df.is_malicious == 1) & (df.technique == t)]
    return set(m["attack_id"].dropna().unique())


def run(out_dir="reports"):
    os.makedirs(out_dir, exist_ok=True)
    if not os.path.exists("data/events.csv"):
        os.makedirs("data", exist_ok=True)
        generate_logs.generate().to_csv("data/events.csv", index=False)
    df = pd.read_csv("data/events.csv", parse_dates=["ts"])

    alerts = R.run_all(df)
    metrics, alert_df, per_tech, detected, all_cases = evaluate(df, alerts)

    # anomaly coverage layer
    feats, flagged = anomaly_score(df)
    mal_users = set(df.loc[df.is_malicious == 1, "user"].dropna().unique())
    flagged_users = set(flagged.index)
    anom_tp = len(flagged_users & mal_users)
    anom_precision = round(anom_tp / len(flagged_users), 3) if len(flagged_users) else 0.0
    # cases the anomaly layer surfaces that rules missed
    missed_cases = all_cases - detected
    user_to_cases = df[df.is_malicious == 1].groupby("user")["attack_id"].agg(lambda s: set(s.dropna()))
    anom_recovered = set()
    for u in (flagged_users & mal_users):
        anom_recovered |= (user_to_cases.get(u, set()) & missed_cases)

    combined_detected = detected | anom_recovered
    combined_recall = round(len(combined_detected) / len(all_cases), 3)

    report = {
        "events": int(len(df)),
        "rule_detection": metrics,
        "anomaly_layer": {"users_flagged": len(flagged_users), "true_positive_users": anom_tp,
                          "precision": anom_precision, "cases_recovered_missed_by_rules": len(anom_recovered)},
        "combined_case_recall": combined_recall,
        "per_technique": per_tech,
        "false_positive_sources": alert_df[alert_df.outcome == "false_positive"]["rule"].value_counts().to_dict(),
    }
    queue = build_queue(alert_df)
    queue.to_csv(f"{out_dir}/alert_queue.csv", index=False)
    alert_df.to_csv(f"{out_dir}/alerts.csv", index=False)
    pd.DataFrame(per_tech).to_csv(f"{out_dir}/per_technique.csv", index=False)
    flagged.reset_index().to_csv(f"{out_dir}/anomaly_flagged.csv", index=False)
    json.dump(report, open(f"{out_dir}/detection_report.json", "w"), indent=2)
    return report, alert_df


if __name__ == "__main__":
    rep, _ = run()
    m = rep["rule_detection"]
    print(f"events {rep['events']:,} | alerts {m['alerts_total']} "
          f"(TP {m['true_positives']}, FP {m['false_positives']})")
    print(f"rule precision {m['precision']} | case recall {m['case_recall']} "
          f"({m['cases_detected']}/{m['cases_total']} cases)")
    print(f"anomaly layer: {rep['anomaly_layer']}")
    print(f"combined recall {rep['combined_case_recall']}")
    print("FP sources:", rep["false_positive_sources"])
    for t in rep["per_technique"]:
        print(f"  {t['technique']} {t['name']}: {t['detected']}/{t['cases']} recall {t['recall']}")
