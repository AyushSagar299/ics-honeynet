"""
observability_ceiling.py -- measure the passive-observability ceiling.

The trivial question ("what variables appear in the packets") is a definition.
The real, measurable question is state inference: given only the variables that
are observable on the wire, how well can the UNOBSERVED variables be reconstructed
from them? This script splits the sensors into observed and hidden, trains a model
on NORMAL data to predict the hidden tags from the observed ones, and reports the
reconstruction quality (R-squared) per hidden tag. That spread is the ceiling: it
bounds how faithful the shadow (and therefore the decoy) can be for state that is
never directly captured.

  python observability_ceiling.py [csv]     (defaults to swat_like.csv)
"""

import os
import sys

import numpy as np
import pandas as pd
from sklearn.linear_model import Ridge
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import r2_score

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "swat_like.csv")


def main():
    if not os.path.exists(CSV):
        print("dataset not found:", CSV)
        return
    df = pd.read_csv(CSV)
    df.columns = [str(c).strip() for c in df.columns]
    label = next((c for c in df.columns
                  if c.lower() in ("normal/attack", "label", "attack", "y", "class")), df.columns[-1])
    normal = df[df[label].astype(str).str.strip().str.lower().isin(["normal", "0", "n", "false", ""])]
    feat = normal.drop(columns=[label]).select_dtypes(include=[np.number])
    feat = feat.drop(columns=[c for c in feat.columns if "time" in c.lower()], errors="ignore")
    feat = feat.loc[:, feat.std() > 1e-9]
    cols = list(feat.columns)

    observed = cols[::2]          # assume every other sensor is visible on the wire
    hidden = cols[1::2]           # the rest are never captured
    Xo = feat[observed].to_numpy(dtype=float)
    Xh = feat[hidden].to_numpy(dtype=float)
    n = len(Xo)
    tr = int(n * 0.7)

    so = StandardScaler().fit(Xo[:tr])
    sh = StandardScaler().fit(Xh[:tr])
    Xo_s, Xh_s = so.transform(Xo), sh.transform(Xh)
    model = Ridge(alpha=1.0).fit(Xo_s[:tr], Xh_s[:tr])
    pred = model.predict(Xo_s[tr:])

    print("=" * 68)
    print("  PASSIVE-OBSERVABILITY CEILING  (state inference from observed tags)")
    print("=" * 68)
    print(f"  observed on the wire : {observed}")
    print(f"  hidden (not captured): {hidden}")
    print("-" * 68)
    print(f"  {'hidden tag':14}{'R^2 (reconstruction)':>22}   inferability")
    r2s = []
    for i, tag in enumerate(hidden):
        r2 = r2_score(Xh_s[tr:, i], pred[:, i])
        r2s.append(r2)
        verdict = "high (shadowable)" if r2 >= 0.7 else "partial" if r2 >= 0.3 else "LOW (a real limit)"
        print(f"  {tag:14}{r2:>22.2f}   {verdict}")
    print("-" * 68)
    print(f"  mean reconstruction R^2 = {np.mean(r2s):.2f}  <-- the measured ceiling")
    print("=" * 68)
    print("  Reading: tags with high R^2 can be shadowed faithfully even though they")
    print("  are never seen on the wire; tags with low R^2 mark the hard limit of a")
    print("  passive shadow. This ceiling bounds decoy fidelity and detection.")
    print("=" * 68)


if __name__ == "__main__":
    main()
