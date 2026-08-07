"""Alert triage: prioritize the queue and draft an analyst summary.

Priority blends alert severity with the criticality of the MITRE technique, so the
queue surfaces the events most worth a human's time first. The summary is drafted
from a prompt template; if an LLM is available (OPENAI_API_KEY set) it is used,
otherwise a deterministic template fills in. This keeps the app dependency-light
while showing the prompt-engineering integration point the JD asks for.
"""
from __future__ import annotations

import os

SEV_WEIGHT = {"critical": 3, "high": 2, "medium": 1, "low": 0}
TECH_WEIGHT = {"T1041": 3, "T1059": 3, "T1548": 2, "T1110": 2, "T1078": 2}


def priority(alert: dict) -> int:
    return SEV_WEIGHT.get(alert.get("severity", "low"), 0) + TECH_WEIGHT.get(alert.get("technique"), 0)


def triage_prompt(alert: dict) -> str:
    """The prompt an analyst-copilot LLM would receive for this alert."""
    return (
        "You are a SOC analyst copilot. Summarize the alert in two sentences, state the "
        "likely MITRE ATT&CK technique, and recommend the next investigation step.\n"
        f"Rule: {alert.get('rule')}\nTechnique: {alert.get('technique')}\n"
        f"Severity: {alert.get('severity')}\nEntity: {alert.get('entity')}\n"
        f"Evidence: {alert.get('detail')}\n"
    )


def summarize(alert: dict) -> str:
    """Use an LLM if configured, else a deterministic template."""
    if os.getenv("OPENAI_API_KEY"):
        try:
            from openai import OpenAI
            client = OpenAI()
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": triage_prompt(alert)}],
                temperature=0.2, max_tokens=120)
            return resp.choices[0].message.content.strip()
        except Exception:
            pass  # fall back to template on any error
    return (f"{alert.get('rule')} on {alert.get('entity')} "
            f"({alert.get('technique')}). Evidence: {alert.get('detail')}. "
            "Next step: confirm the source is expected for this entity and check for related activity.")


def build_queue(alert_df):
    q = alert_df.copy()
    q["priority"] = q.apply(lambda r: priority(r.to_dict()), axis=1)
    q["summary"] = q.apply(lambda r: summarize(r.to_dict()), axis=1)
    return q.sort_values(["priority", "outcome"], ascending=[False, True]).reset_index(drop=True)
