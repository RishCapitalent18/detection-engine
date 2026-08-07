# Build It Yourself - Detection Engineering Lab (Windows / PowerShell)

Build it in stages so it is yours. Files in `detection/` are the answer key. Where
you see **YOUR CALL**, pick the value and be ready to defend it in an interview.

## Step 0 - setup

```powershell
cd $HOME\Documents
mkdir detection-engine; cd detection-engine
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install pandas numpy scikit-learn streamlit plotly pytest
mkdir detection, app, tests, data, reports
New-Item detection\__init__.py -ItemType File
```

## Step 1 - labeled telemetry (`generate_logs.py`)

Generate auth, process, and network events. Inject attacks and label each with an
attack_id and a MITRE technique. Crucially, mix in benign-but-suspicious noise
(reset storms, backups, admin sudo) so your detections have real false positives.

**YOUR CALL:** how obvious to make each attack. Leave one brute force low-and-slow,
under whatever threshold you pick, so your recall number is honest.

## Step 2 - detections (`rules.py`)

Write one function per technique, each returning the event indices it fired on (you
need those to score honestly). Map each to its MITRE ID. **YOUR CALL:** the
thresholds - brute-force count, exfil byte size, impossible-travel distance/time.

## Step 3 - anomaly layer (`anomaly.py`)

Build per-user behavior features (login count, failures, distinct countries/IPs) and
flag outliers with an Isolation Forest. This is your coverage net for novel behavior.
Keep it openly lower-precision than the rules.

## Step 4 - honest scoring (`pipeline.py`)

Score alerts against the labels: precision, per-technique recall, false positives by
rule. If your precision is 1.0, you are probably only detecting the obvious injected
attacks - add benign noise until it is realistic.

## Step 5 - triage (`triage.py`)

Rank the queue by severity plus technique criticality, and draft a one-line summary.
Write it around a prompt template so an LLM can fill it in when a key is present.

```powershell
python run_pipeline.py
streamlit run app\streamlit_app.py
pytest -q
```

## Make it yours

1. Add a technique (lateral movement, persistence) with its own rule and label.
2. Track ATT&CK coverage - which techniques you can and cannot yet detect.
3. Add per-rule precision tuning and show the before/after.
4. Wire the LLM triage to a real key and compare its summaries to the template.

## Honest framing

"I built this to show detection engineering: MITRE-mapped rules, an anomaly layer,
and honest fidelity scoring with the false positives on display. I came from alert
triage and incident response, and this is me building the detections themselves."
