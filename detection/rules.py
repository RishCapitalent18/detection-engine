"""Rule-based detections, each mapped to a MITRE ATT&CK technique.

Every rule returns alerts as dicts with the triggering event indices, so the
pipeline can score them honestly against the labeled ground truth. Rules are
tuned for high precision on known techniques; the anomaly layer handles novelty.
"""
from __future__ import annotations

import re
import numpy as np
import pandas as pd

GEO = {"US": (38, -97), "IN": (22, 79), "GB": (54, -2), "DE": (51, 10), "RU": (61, 99), "BR": (-10, -55)}


def _haversine(a, b):
    (la1, lo1), (la2, lo2) = a, b
    la1, lo1, la2, lo2 = map(np.radians, [la1, lo1, la2, lo2])
    h = np.sin((la2-la1)/2)**2 + np.cos(la1)*np.cos(la2)*np.sin((lo2-lo1)/2)**2
    return 2 * 6371 * np.arcsin(np.sqrt(h))


def _alert(rule, technique, severity, entity, idx, detail):
    return {"rule": rule, "technique": technique, "severity": severity,
            "entity": entity, "event_idx": list(idx), "detail": detail}


def brute_force(df, min_failures=18):
    """T1110: many failed logins from one source to one account in a short span."""
    a = df[(df.event_type == "auth") & (df.action == "login_failure")]
    out = []
    for (user, ip), g in a.groupby(["user", "src_ip"]):
        if len(g) >= min_failures and (g.ts.max() - g.ts.min()) <= pd.Timedelta(hours=2):
            out.append(_alert("Brute force", "T1110", "high", f"{user}@{ip}",
                              g.index.tolist(), f"{len(g)} failed logins in <2h"))
    return out


def impossible_travel(df, hours=2, km=3000):
    """T1078: same user, two successful logins from far-apart countries, too fast."""
    s = df[(df.event_type == "auth") & (df.action == "login_success")].sort_values("ts")
    out = []
    for user, g in s.groupby("user"):
        rows = g[["ts", "country"]].reset_index()
        for i in range(1, len(rows)):
            c1, c2 = rows.country[i-1], rows.country[i]
            if c1 != c2 and c1 in GEO and c2 in GEO:
                dt = (rows.ts[i] - rows.ts[i-1]).total_seconds() / 3600
                if dt <= hours and _haversine(GEO[c1], GEO[c2]) >= km:
                    out.append(_alert("Impossible travel", "T1078", "high", user,
                                      [rows["index"][i-1], rows["index"][i]],
                                      f"{c1}->{c2} in {dt:.1f}h"))
    return out


SUSPICIOUS = [r"curl\s+http", r"wget\s+http", r"base64\s+-d", r"/tmp/\.",
              r"chmod\s+\+x\s+/tmp", r"\|\s*bash", r"-c.*socket"]


def suspicious_process(df):
    """T1059: command-and-scripting indicators (download-and-run, encoded payloads)."""
    p = df[df.event_type == "process"]
    pat = re.compile("|".join(SUSPICIOUS))
    out = []
    for i, row in p.iterrows():
        if isinstance(row.cmdline, str) and pat.search(row.cmdline):
            out.append(_alert("Suspicious process", "T1059", "critical", row.host,
                              [i], row.cmdline[:60]))
    return out


def privilege_escalation(df):
    """T1548: sudo to root / adding a user to sudoers / interactive root shell."""
    p = df[(df.event_type == "process") & (df.process == "sudo")]
    pat = re.compile(r"su\s*-|usermod\s+-aG\s+sudo|bash\s+-i")
    out = []
    for i, row in p.iterrows():
        if isinstance(row.cmdline, str) and pat.search(row.cmdline):
            out.append(_alert("Privilege escalation", "T1548", "high", row.host, [i], row.cmdline))
    return out


def exfiltration(df, threshold=100_000_000):
    """T1041: large outbound transfer to an external host."""
    n = df[(df.event_type == "network") & (df.bytes_out > threshold)]
    return [_alert("Data exfiltration", "T1041", "critical", row.host, [i],
                   f"{row.bytes_out/1e6:.0f} MB to {row.dst_ip}") for i, row in n.iterrows()]


def run_all(df):
    alerts = []
    for fn in (brute_force, impossible_travel, suspicious_process, privilege_escalation, exfiltration):
        alerts.extend(fn(df))
    return alerts
