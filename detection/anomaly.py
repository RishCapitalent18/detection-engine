"""Anomaly layer for novel signals the rules do not encode (T1078/behavioral).

Builds per-user authentication behavior features and flags outliers with an
Isolation Forest. Lower precision than the rules by design - this is the coverage
layer, and its hits are meant to be reviewed, not auto-actioned.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def user_features(df):
    a = df[df.event_type == "auth"]
    g = a.groupby("user")
    feats = pd.DataFrame({
        "logins": g.size(),
        "failures": a[a.action == "login_failure"].groupby("user").size(),
        "distinct_ips": g["src_ip"].nunique(),
        "distinct_countries": g["country"].nunique(),
        "distinct_hosts": g["host"].nunique(),
    }).fillna(0)
    feats["failure_ratio"] = feats["failures"] / feats["logins"].clip(lower=1)
    return feats


def score(df, contamination=0.06, seed=0):
    feats = user_features(df).copy()
    X = feats.values
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    feats["anomaly"] = model.fit_predict(X)
    feats["anomaly_score"] = -model.score_samples(X)
    flagged = feats[feats["anomaly"] == -1].sort_values("anomaly_score", ascending=False)
    return feats, flagged
