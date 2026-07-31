"""
swat_detector.py -- the REAL anomaly-detection pipeline, for SWaT (or any
SWaT-format CSV).

Unlike the earlier demo detector, this one is honest and non-circular:
  - it trains on NORMAL data only,
  - it uses the RAW sensor columns (no hand-crafted feature that encodes the answer),
  - there is no leakage (the scaler is fit on the training data only, and the
    alarm threshold is chosen on the training data only),
  - it reports the metrics a tribunal expects: PR-AUC (the headline, because
    attacks are rare), F1, point-adjusted F1, recall, false-alarms per day,
    detection delay, and per-attack coverage.
It compares Isolation Forest, One-Class SVM and PCA reconstruction.

  .venv/bin/python swat_detector.py [path-to-csv]   (windows: .venv\\Scripts\\python.exe)
  (defaults to ai/swat_like.csv, a stand-in until the real SWaT arrives)
"""

import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score, precision_recall_fscore_support

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "swat_like.csv")
SAMPLE_HZ = 1.0     # SWaT is one sample per second


def load(path):
    df = pd.read_csv(path)
    df.columns = [str(c).strip() for c in df.columns]
    label_col = None
    for c in df.columns:
        if c.lower() in ("normal/attack", "label", "attack", "y", "class"):
            label_col = c
            break
    if label_col is None:
        label_col = df.columns[-1]

    def to_y(v):
        s = str(v).strip().lower()
        return 0 if s in ("normal", "0", "false", "n", "") else 1

    y = df[label_col].map(to_y).to_numpy()
    feat = df.drop(columns=[label_col]).select_dtypes(include=[np.number])
    feat = feat.loc[:, feat.std(numeric_only=True) > 1e-9]
    return feat.to_numpy(dtype=float), y, list(feat.columns)


def segments(y):
    i, n = 0, len(y)
    while i < n:
        if y[i] == 1:
            j = i
            while j < n and y[j] == 1:
                j += 1
            yield i, j
            i = j
        else:
            i += 1


def point_adjust(pred, y):
    pa = pred.copy()
    for a, b in segments(y):
        if pred[a:b].any():
            pa[a:b] = 1
    return pa


def detection_delay(pred, y):
    d = []
    for a, b in segments(y):
        seg = pred[a:b]
        d.append(int(np.argmax(seg)) if seg.any() else (b - a))
    return float(np.mean(d)) if d else float("nan")


def evaluate(name, train_score, test_score, yte, out):
    thr = np.percentile(train_score, 99.5)                 # threshold from TRAIN only
    pred = (test_score > thr).astype(int)
    _, _, f, _ = precision_recall_fscore_support(yte, pred, average="binary", zero_division=0)
    pa = point_adjust(pred, yte)
    _, _, fadj, _ = precision_recall_fscore_support(yte, pa, average="binary", zero_division=0)
    _, recall, _, _ = precision_recall_fscore_support(yte, pred, average="binary", zero_division=0)
    try:
        auc = average_precision_score(yte, test_score)
    except ValueError:
        auc = float("nan")
    fp = int(((pred == 1) & (yte == 0)).sum())
    days = len(yte) / (SAMPLE_HZ * 86400)
    fa_day = fp / days if days > 0 else float("nan")
    delay = detection_delay(pred, yte) / SAMPLE_HZ
    segs = list(segments(yte))
    caught = sum(1 for a, b in segs if pred[a:b].any())
    out(f"  {name:20}{auc:8.2f}{f:8.2f}{fadj:8.2f}{recall:8.2f}{fa_day:10.1f}{delay:10.0f}   {caught}/{len(segs)}")


def main():
    if not os.path.exists(CSV):
        print("dataset not found:", CSV)
        print("generate the stand-in first: ", sys.executable, "make_swat_like.py")
        return
    X, y, cols = load(CSV)
    first_atk = int(np.argmax(y == 1)) if (y == 1).any() else len(y)
    split = max(int(len(y) * 0.5), first_atk)
    Xtr = X[:split][y[:split] == 0]                        # NORMAL only
    Xte, yte = X[split:], y[split:]
    scaler = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)

    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out("=" * 82)
    out("  SWaT-STYLE ANOMALY DETECTION  (train on NORMAL only, no leakage, raw features)")
    out("=" * 82)
    out(f"  file: {os.path.basename(CSV)}   features: {len(cols)}   "
        f"train(normal): {len(Xtr)}   test: {len(Xte)}   attacks in test: {int(yte.sum())}")
    out("-" * 82)
    out(f"  {'Model':20}{'PR-AUC':>8}{'F1':>8}{'F1adj':>8}{'Recall':>8}{'FA/day':>10}{'delay(s)':>10}  cover")

    iso = IsolationForest(n_estimators=200, random_state=0).fit(Xtr_s)
    evaluate("Isolation Forest", -iso.score_samples(Xtr_s), -iso.score_samples(Xte_s), yte, out)

    rs = np.random.RandomState(0)
    sub = Xtr_s[rs.choice(len(Xtr_s), min(len(Xtr_s), 8000), replace=False)]
    oc = OneClassSVM(nu=0.05, gamma="scale").fit(sub)
    evaluate("One-Class SVM", -oc.score_samples(sub), -oc.score_samples(Xte_s), yte, out)

    k = max(1, min(10, Xtr_s.shape[1] // 2))
    pca = PCA(n_components=k).fit(Xtr_s)
    tr_err = np.mean((Xtr_s - pca.inverse_transform(pca.transform(Xtr_s))) ** 2, axis=1)
    te_err = np.mean((Xte_s - pca.inverse_transform(pca.transform(Xte_s))) ** 2, axis=1)
    evaluate("PCA reconstruction", tr_err, te_err, yte, out)

    out("=" * 82)
    out("  PR-AUC is the headline metric (attacks are rare). F1adj is point-adjusted F1")
    out("  (a whole attack segment counts as caught if ANY point in it is flagged); it is")
    out("  more generous, so it is shown next to the raw F1 for honesty. FA/day and the")
    out("  detection delay are what an operator actually cares about.")
    out("=" * 82)
    with open(os.path.join(HERE, "swat_results.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
