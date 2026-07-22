"""
smart_detector.py -- the SMART brain of the honeynet.

Instead of a hand-written threshold, the honeynet LEARNS what normal plant
behaviour looks like and then flags attacker activity as anomalies -- by itself.
It trains and compares three unsupervised machine-learning models
(Isolation Forest, One-Class SVM, and a PCA reconstruction detector) and reports
how well each one catches attacks.

This is the machine-learning / "Intelligent Systems" contribution: a learned
model of "normal" that detects deviations -- attacker-injected register values,
spoofed sensors, and physically-impossible states.

  python smart_detector.py     # train, evaluate, print a comparison, save the model

The normal data reproduces the real plant's physics (tank_plc.py):
level is a 40-80% saw-tooth, and pressure = level * 0.1. Attacks are injected
for evaluation. You can later swap in SWaT/WADI for benchmark numbers.
"""

import os
import random

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
import joblib

random.seed(0)
np.random.seed(0)
HERE = os.path.dirname(os.path.abspath(__file__))


def simulate_normal(n=4000):
    """Reproduce tank_plc.py physics, including the x10 register rounding."""
    level, temp, pump, heater, valve = 50.0, 22.0, 0, 0, 1
    rows = []
    for _ in range(n):
        if level < 40:
            pump = 1
        elif level > 80:
            pump = 0
        if temp < 55:
            heater = 1
        elif temp > 60:
            heater = 0
        if pump:
            level += 1.0
        if valve:
            level -= 0.5
        level = max(0.0, min(100.0, level))
        temp += 0.4 if heater else -0.2
        temp += random.uniform(-0.05, 0.05)
        temp = max(18.0, min(80.0, temp))
        pressure = level * 0.1
        # the real PLC stores values x10 as ints, so reproduce that rounding
        rows.append([int(level * 10) / 10, int(temp * 10) / 10, int(pressure * 10) / 10,
                     pump, heater, valve])
    return np.array(rows, dtype=float)


def featurize(X):
    """Add a physics-consistency feature: pressure should equal level * 0.1."""
    p_residual = X[:, 2] - X[:, 0] * 0.1
    return np.column_stack([X[:, 0], X[:, 1], X[:, 2], X[:, 3], X[:, 4], X[:, 5], p_residual])


def inject_attacks(X, frac=0.15):
    """Mark 15% of rows as attacker-caused anomalies (all detectable per-sample)."""
    X = X.copy()
    y = np.zeros(len(X), dtype=int)
    idx = np.random.choice(len(X), int(len(X) * frac), replace=False)
    for i in idx:
        kind = random.choice(["inject", "spoof_pressure", "temp_tamper", "sensor_drop"])
        if kind == "inject":            # attacker writes an impossible level
            X[i, 0] = random.choice([123.4, 999.0, 0.0])
        elif kind == "spoof_pressure":  # pressure inconsistent with level
            X[i, 2] = X[i, 0] * 0.1 + 3.0
        elif kind == "temp_tamper":     # impossible temperature
            X[i, 1] = 95.0
        elif kind == "sensor_drop":     # pressure reads 0 while level is normal
            X[i, 2] = 0.0
        y[i] = 1
    return X, y


def main():
    Xn = simulate_normal(4000)
    scaler = StandardScaler().fit(featurize(Xn))
    Fn = scaler.transform(featurize(Xn))

    Xt = simulate_normal(2000)
    Xt_atk, y = inject_attacks(Xt)
    Ft = scaler.transform(featurize(Xt_atk))

    results = {}

    iso = IsolationForest(n_estimators=300, contamination=0.03, random_state=0).fit(Fn)
    results["Isolation Forest"] = ((iso.predict(Ft) == -1).astype(int), -iso.score_samples(Ft))

    oc = OneClassSVM(nu=0.02, gamma="scale").fit(Fn)
    results["One-Class SVM"] = ((oc.predict(Ft) == -1).astype(int), -oc.score_samples(Ft))

    pca = PCA(n_components=3).fit(Fn)
    err_tr = np.mean((Fn - pca.inverse_transform(pca.transform(Fn))) ** 2, axis=1)
    thr = np.percentile(err_tr, 99)
    err = np.mean((Ft - pca.inverse_transform(pca.transform(Ft))) ** 2, axis=1)
    results["PCA reconstruction"] = ((err > thr).astype(int), err)

    print("=" * 70)
    print("  SMART ANOMALY DETECTION  --  the honeynet's learned brain")
    print("  trained on NORMAL plant behaviour; tested on injected attacks")
    print("=" * 70)
    print(f"  test samples: {len(y)}    attacks: {int(y.sum())}    normal: {int((y == 0).sum())}")
    print("-" * 70)
    print(f"  {'Model':22}{'Precision':>11}{'Recall':>9}{'F1':>8}{'ROC-AUC':>10}")
    best = ("", -1.0)
    for name, (pred, score) in results.items():
        p = precision_score(y, pred, zero_division=0)
        r = recall_score(y, pred, zero_division=0)
        f = f1_score(y, pred, zero_division=0)
        try:
            auc = roc_auc_score(y, score)
        except ValueError:
            auc = float("nan")
        print(f"  {name:22}{p:11.2f}{r:9.2f}{f:8.2f}{auc:10.2f}")
        if f > best[1]:
            best = (name, f)
    print("=" * 70)
    print(f"  best model: {best[0]}  (F1 = {best[1]:.2f})")

    joblib.dump({"model": oc, "scaler": scaler,
                 "features": ["level", "temp", "pressure", "pump", "heater", "valve", "p_residual"]},
                os.path.join(HERE, "detector.joblib"))
    print("  saved trained detector -> ai/detector.joblib")
    print("  -> the honeynet now LEARNS normal and flags attacks automatically.")


if __name__ == "__main__":
    main()
