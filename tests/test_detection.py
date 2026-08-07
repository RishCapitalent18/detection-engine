"""Tests for the detection rules, anomaly layer, and honest scoring."""
import pandas as pd
import pytest

from detection import generate_logs
from detection import rules as R
from detection.pipeline import evaluate
from detection.anomaly import score as anomaly_score


@pytest.fixture(scope="module")
def data():
    return generate_logs.generate()


def test_dataset_has_labeled_attacks(data):
    assert data["is_malicious"].sum() > 100
    assert data.loc[data.is_malicious == 1, "attack_id"].nunique() >= 30
    assert set(data.loc[data.is_malicious == 1, "technique"]) >= {"T1110", "T1078", "T1059", "T1548", "T1041"}


def test_rules_detect_most_cases_with_some_false_positives(data):
    alerts = R.run_all(data)
    metrics, _, _, _, _ = evaluate(data, alerts)
    assert 0.75 <= metrics["precision"] < 1.0          # realistic: not perfect precision
    assert 0.85 <= metrics["case_recall"] <= 1.0       # catches most known techniques
    assert metrics["false_positives"] > 0              # benign noise trips some rules


def test_exfil_rule_flags_large_transfers(data):
    alerts = R.exfiltration(data)
    assert len(alerts) >= 5
    assert all(a["technique"] == "T1041" for a in alerts)


def test_brute_force_ignores_low_volume(data):
    # the low-and-slow case (11 failures) must stay under the threshold
    alerts = R.brute_force(data, min_failures=18)
    metrics, _, _, detected, all_cases = evaluate(data, alerts)
    assert len(all_cases - detected) >= 1              # at least one case slips past the rule


def test_anomaly_layer_flags_outliers(data):
    feats, flagged = anomaly_score(data)
    assert len(flagged) > 0
    assert "anomaly_score" in feats.columns
