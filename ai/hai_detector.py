"""
hai_detector.py -- the anomaly-detection pipeline on the REAL HAI dataset.

HAI ships separate train files (all normal) and test files (with labelled
attacks), which gives a clean, honest, non-circular evaluation: the detector is
trained only on the normal file and never sees an attack until test time.
Same models and metrics as swat_detector.py -- Isolation Forest, One-Class SVM,
PCA reconstruction, reported with PR-AUC, F1, point-adjusted F1, recall,
detection delay, false-alarms per day, and per-attack coverage.

  python hai_detector.py [train_csv] [test_csv]
  default: hai-21.03/train1.csv (normal)  +  hai-21.03/test1.csv (attacks)
"""

import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from swat_detector import evaluate  # reuse the exact metrics/reporting

HAI = r"C:\Users\AyushAgar\.cache\kagglehub\datasets\icsdataset\hai-security-dataset\versions\10"
TRAIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HAI, "hai-21.03", "train1.csv")
TEST = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HAI, "hai-21.03", "test1.csv")

DROP = {"time", "timestamp", "attack", "attack_p1", "attack_p2", "attack_p3"}


def load(path):
    df = pd.read_csv(path)
    df.columns = [str(c).strip() for c in df.columns]
    lab = next((c for c in df.columns if c.lower() == "attack"), None)
    y = (df[lab].astype(float) > 0).astype(int).to_numpy() if lab else np.zeros(len(df), dtype=int)
    feat = df[[c for c in df.columns if c.lower() not in DROP]].select_dtypes(include=[np.number])
    return feat, y


def main():
    print("loading HAI (this reads a large train file, ~10-20s) ...", flush=True)
    ftr, _ = load(TRAIN)                 # train file is all-normal
    fte, yte = load(TEST)
    common = [c for c in ftr.columns if c in fte.columns]
    Xtr = ftr[common].to_numpy(float)
    Xte = fte[common].to_numpy(float)
    keep = Xtr.std(axis=0) > 1e-9        # drop constant sensors, decided on train only
    Xtr, Xte = Xtr[:, keep], Xte[:, keep]
    scaler = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)

    lines = []

    def out(s=""):
        print(s, flush=True)
        lines.append(s)

    out("=" * 84)
    out("  HAI ANOMALY DETECTION  (REAL DATA: train on the normal file, test on the attack file)")
    out("=" * 84)
    out(f"  train: {os.path.basename(TRAIN)}  ({len(Xtr)} rows, all normal)")
    out(f"  test : {os.path.basename(TEST)}  ({len(Xte)} rows, {int(yte.sum())} attack)   "
        f"features: {Xtr_s.shape[1]}")
    out("-" * 84)
    out(f"  {'Model':20}{'PR-AUC':>8}{'F1':>8}{'F1adj':>8}{'Recall':>8}{'FA/day':>10}{'delay(s)':>10}  cover")

    iso = IsolationForest(n_estimators=200, random_state=0).fit(Xtr_s)
    evaluate("Isolation Forest", -iso.score_samples(Xtr_s), -iso.score_samples(Xte_s), yte, out)

    rs = np.random.RandomState(0)
    sub = Xtr_s[rs.choice(len(Xtr_s), min(len(Xtr_s), 8000), replace=False)]
    oc = OneClassSVM(nu=0.05, gamma="scale").fit(sub)
    evaluate("One-Class SVM", -oc.score_samples(sub), -oc.score_samples(Xte_s), yte, out)

    k = max(1, min(15, Xtr_s.shape[1] // 3))
    pca = PCA(n_components=k).fit(Xtr_s)
    tr_err = np.mean((Xtr_s - pca.inverse_transform(pca.transform(Xtr_s))) ** 2, axis=1)
    te_err = np.mean((Xte_s - pca.inverse_transform(pca.transform(Xte_s))) ** 2, axis=1)
    evaluate("PCA reconstruction", tr_err, te_err, yte, out)

    out("=" * 84)
    out("  Real HAI data. The train file is all-normal, so the detector never saw the attacks")
    out("  before test time -- this is the honest, non-circular result for the thesis.")
    out("=" * 84)
    with open(os.path.join(HERE, "hai_results.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
