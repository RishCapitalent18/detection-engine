"""Run the detection pipeline end to end: generate logs, run rules + anomaly
layer, score fidelity, triage the queue, and write artifacts to reports/."""
import json
import os
from detection import generate_logs
from detection.pipeline import run

if __name__ == "__main__":
    if not os.path.exists("data/events.csv"):
        os.makedirs("data", exist_ok=True)
        generate_logs.generate().to_csv("data/events.csv", index=False)
        print("generated security logs")
    rep, _ = run()
    m = rep["rule_detection"]
    print(f"alerts {m['alerts_total']} | precision {m['precision']} | recall {m['case_recall']} "
          f"| combined recall {rep['combined_case_recall']}")
    print("artifacts written to reports/")
