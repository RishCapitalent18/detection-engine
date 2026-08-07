# Detection Engineering Lab

A small detection-engineering project: rule-based detections mapped to MITRE
ATT&CK over synthetic security telemetry, an anomaly layer for novel signals, an
honest fidelity evaluation against labeled ground truth, and an alert-triage queue.

Built with Python, scikit-learn, and Streamlit.

---

## What it does

1. **Generate telemetry.** Synthetic auth, process, and network events, with a set
   of attacks injected and labeled by MITRE technique so detections can be scored
   honestly. Benign-but-suspicious noise (password-reset storms, backup transfers,
   admin sudo) is mixed in so false positives are real.
2. **Detect.** Five rules, each tied to a MITRE technique:
   - T1110 Brute Force - many failed logins from one source in a short span
   - T1078 Valid Accounts - impossible travel (same user, far-apart countries, fast)
   - T1059 Command and Scripting - download-and-run and encoded-payload indicators
   - T1548 Privilege Escalation - sudo-to-root / sudoers changes
   - T1041 Exfiltration - large outbound transfer to an external host
3. **Add an anomaly layer.** An Isolation Forest over per-user auth behavior flags
   outliers the rules do not encode (it recovers the low-and-slow brute force the
   threshold rule misses).
4. **Score honestly.** Precision, case recall, per-technique recall, and a
   false-positive breakdown, all against the labeled ground truth.
5. **Triage.** Alerts are prioritized by severity and technique criticality, with a
   drafted analyst summary (prompt template, swappable for an LLM).

## Results on the sample data (about 47K events, 40 injected attacks)

- **Rule precision ~0.80** - 13 false positives from the benign noise (admin sudo,
  backups, reset storms). Cutting these is the real engineering work.
- **Case recall 0.975** - 39 of 40 attacks caught by rules. The miss is a
  low-and-slow brute force under the threshold.
- **Anomaly layer** flags 12 users (about 11 truly suspicious) and recovers the
  missed case, taking combined recall to full coverage on this labeled set.
- Per technique: exfiltration, suspicious process, impossible travel, and
  privilege escalation all at full recall; brute force at 0.90.

These numbers are meant to be believable, not perfect. High recall is expected for
known indicators; the honest challenge is precision (false-positive reduction),
which is exactly what the tuning view highlights.

## Quickstart

```bash
pip install -r requirements-dev.txt
python run_pipeline.py                 # generate logs, detect, score, triage -> reports/
pytest -q

pip install -r requirements.txt
streamlit run app/streamlit_app.py     # SOC dashboard over the artifacts
```

Set `OPENAI_API_KEY` to have alert summaries drafted by an LLM instead of the
template (see `detection/triage.py` for the prompt).

## Design notes

- **Honest evaluation.** Every rule returns the event indices it fired on, so alerts
  are scored against labeled attacks - true positives, false positives, and
  per-technique recall are measured, not asserted.
- **Precision over bravado.** Rules are tuned for high precision on known techniques.
  The anomaly layer is the coverage net and is openly lower precision.
- **Triage that saves time.** The queue is ordered so the highest-risk events sit on
  top, with a summary and a next step for each.
- **Tested.** The suite checks the attacks are labeled, that rules catch most cases
  while still producing false positives, and that the low-and-slow case slips the
  threshold (so recall is honest).

## Repo layout

```
detection-engine/
+-- run_pipeline.py             # end-to-end run
+-- detection/
|   +-- generate_logs.py        # synthetic telemetry + labeled MITRE attacks
|   +-- rules.py                # MITRE-mapped detection rules
|   +-- anomaly.py              # Isolation Forest coverage layer
|   +-- triage.py               # priority scoring + LLM-pluggable summaries
|   +-- pipeline.py             # orchestration + honest scoring
+-- app/streamlit_app.py        # SOC dashboard
+-- tests/test_detection.py     # unit tests
+-- reports/                    # committed artifacts the dashboard reads
```

> Telemetry is fully synthetic and generated locally. No real security data is used.
