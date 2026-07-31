"""
make_swat_like.py -- generate a SWaT-FORMAT stand-in dataset.

This is a placeholder so the real pipeline (swat_detector.py) can be tested end
to end BEFORE the real SWaT dataset request is approved. It builds a correlated
multivariate process (ten sensors) with realistic normal behaviour, then injects
four labelled attack windows (offset, stuck sensor, slow drift, spike) into the
test half. The columns and the Normal/Attack label follow the SWaT layout, so
swat_detector.py runs on this file exactly as it will on the real one.

  IMPORTANT: this is NOT real data. When your SWaT request is approved, run the
  detector on the real CSV instead:  .venv/bin/python swat_detector.py <real-SWaT.csv>
  (on windows that is .venv\\Scripts\\python.exe swat_detector.py <real-SWaT.csv>)
"""

import os

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
rng = np.random.RandomState(0)
N = 20000
t = np.arange(N)

f1 = np.sin(2 * np.pi * t / 1500)
f2 = np.sin(2 * np.pi * t / 900 + 1.0)
f3 = (t % 2000) / 2000.0

cols = ["FIT101", "LIT101", "MV101", "P101", "AIT201",
        "FIT201", "LIT301", "P301", "PIT501", "FIT601"]
base = {
    "FIT101": 2.5 + 0.3 * f1,
    "LIT101": 700 + 80 * f3,
    "MV101": 1 + 0.5 * np.sign(np.sin(2 * np.pi * t / 800)),
    "P101": 1 + 0.4 * f2,
    "AIT201": 250 + 15 * f1,
    "FIT201": 2.4 + 0.25 * f2,
    "LIT301": 900 + 60 * f3,
    "P301": 1 + 0.3 * f1,
    "PIT501": 250 + 10 * f2,
    "FIT601": 1.7 + 0.2 * f1,
}
X = np.column_stack([base[c] + rng.normal(0, 0.05 * (np.ptp(base[c]) or 1.0), N) for c in cols])

y = np.zeros(N, dtype=int)
std0 = X[:10000].std(axis=0)
attacks = [(11000, 11300, 0, "offset"),
           (13000, 13250, 4, "stuck"),
           (15000, 15400, 1, "drift"),
           (17000, 17200, 8, "spike")]
for a, b, ci, kind in attacks:
    if kind == "offset":
        X[a:b, ci] += 3 * std0[ci]
    elif kind == "stuck":
        X[a:b, ci] = X[a, ci]
    elif kind == "drift":
        X[a:b, ci] += np.linspace(0, 4 * std0[ci], b - a)
    elif kind == "spike":
        X[a:b, ci] += 6 * std0[ci] * rng.rand(b - a)
    y[a:b] = 1

df = pd.DataFrame(X, columns=cols)
df.insert(0, "Timestamp", t)
df["Normal/Attack"] = np.where(y == 1, "Attack", "Normal")
# pin the line ending so the file comes out byte-identical on windows and macos
df.to_csv(os.path.join(HERE, "swat_like.csv"), index=False, lineterminator="\n")
print(f"wrote swat_like.csv: {N} rows, {int(y.sum())} attack rows, {len(cols)} sensors, {len(attacks)} attack windows")
