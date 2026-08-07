"""Detection-engineering SOC dashboard (reads precomputed artifacts).

Run:  streamlit run app/streamlit_app.py
"""
import json
import os
import sys

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
st.set_page_config(page_title="Detection Engineering Lab", layout="wide")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REP = os.path.join(BASE, "reports")


@st.cache_data
def load():
    rep = json.load(open(os.path.join(REP, "detection_report.json")))
    queue = pd.read_csv(os.path.join(REP, "alert_queue.csv"))
    per_tech = pd.read_csv(os.path.join(REP, "per_technique.csv"))
    return rep, queue, per_tech


if not os.path.exists(os.path.join(REP, "detection_report.json")):
    st.error("No artifacts. Run `python run_pipeline.py` first.")
    st.stop()

rep, queue, per_tech = load()
rd = rep["rule_detection"]
an = rep["anomaly_layer"]

st.title("Detection Engineering Lab")
st.caption("Rule-based detections mapped to MITRE ATT&CK, an anomaly layer for novel signals, "
           "honest fidelity scoring, and alert triage. Synthetic telemetry, labeled ground truth.")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Events analyzed", f"{rep['events']:,}")
c2.metric("Alerts", f"{rd['alerts_total']}")
c3.metric("Rule precision", f"{rd['precision']:.2f}")
c4.metric("Case recall (rules)", f"{rd['case_recall']:.2f}")
c5.metric("Combined recall", f"{rep['combined_case_recall']:.2f}")

tabs = st.tabs(["MITRE coverage", "Alert queue", "Fidelity & tuning"])

with tabs[0]:
    st.subheader("Detection coverage by MITRE ATT&CK technique")
    pt = per_tech.copy()
    pt["label"] = pt["technique"] + " " + pt["name"]
    fig = px.bar(pt, x="recall", y="label", orientation="h", text="detected",
                 range_x=[0, 1.05], labels={"recall": "Case recall", "label": ""})
    fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(per_tech, use_container_width=True, hide_index=True)
    st.caption("Rules catch known techniques at high recall. The one missed case is a low-and-slow "
               "brute force under the rule threshold, recovered by the anomaly layer.")

with tabs[1]:
    st.subheader("Triaged alert queue (highest priority first)")
    f1, f2 = st.columns(2)
    sev = f1.multiselect("Severity", sorted(queue["severity"].unique()),
                         default=sorted(queue["severity"].unique()))
    oc = f2.multiselect("Outcome", sorted(queue["outcome"].unique()),
                        default=sorted(queue["outcome"].unique()))
    view = queue[queue["severity"].isin(sev) & queue["outcome"].isin(oc)]
    st.dataframe(view[["priority", "severity", "technique", "rule", "entity", "detail", "outcome", "summary"]],
                 use_container_width=True, height=380)
    st.caption("Priority blends alert severity with MITRE technique criticality. Summaries are drafted "
               "from a prompt template (swappable for an LLM when an API key is set).")

with tabs[2]:
    st.subheader("Detection fidelity")
    a, b = st.columns(2)
    with a:
        st.markdown("**Alert outcomes**")
        oc = pd.DataFrame({"outcome": ["true positive", "false positive"],
                           "count": [rd["true_positives"], rd["false_positives"]]})
        fig = px.pie(oc, names="outcome", values="count", hole=0.45,
                     color="outcome", color_discrete_map={"true positive": "#2e7d32", "false positive": "#c0392b"})
        fig.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
    with b:
        st.markdown("**False positives by rule (tuning backlog)**")
        fps = pd.DataFrame(list(rep["false_positive_sources"].items()), columns=["rule", "count"])
        fig = px.bar(fps, x="count", y="rule", orientation="h", text="count")
        fig.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)
    st.markdown(f"**Anomaly layer:** flagged {an['users_flagged']} users, "
                f"{an['true_positive_users']} malicious (precision {an['precision']:.2f}), "
                f"recovering {an['cases_recovered_missed_by_rules']} case the rules missed.")
    st.caption("The honest tradeoff: rules are high-precision on known techniques, the anomaly layer "
               "adds coverage at lower precision. Most engineering effort goes into cutting the false positives above.")

with st.expander("Full detection report (JSON)"):
    st.json(rep)
