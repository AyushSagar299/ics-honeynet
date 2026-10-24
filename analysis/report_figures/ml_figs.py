# report figures 6.1, 6.2 and 7.7: the synthetic stand-in, the train/test split and
# the precision-recall curves. it reuses the functions from ai/ so the models are
# exactly the ones in the results files. needs ai/swat_like.csv (make_swat_like.py).
#   .venv/bin/python analysis/report_figures/ml_figs.py
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from style import plt, save, C, GREY, ATTACK, REPO, FIGS
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(REPO, "ai"))
import numpy as np
import pandas as pd
from swat_detector import load, segments
from temporal_detector import (WINDOW, HIDDEN, EPOCHS, normal_runs, windows,
                               train_ae, window_scores, drop_counter_cols)
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score, precision_recall_curve

CSV = os.path.join(REPO, "ai", "swat_like.csv")
facts = {}
raw = pd.read_csv(CSV)
X, y, cols = load(CSV)
X, cols, dropped = drop_counter_cols(X, cols)
N = len(y)
facts["rows"] = N
facts["features"] = cols
facts["attack_rows_total"] = int(y.sum())
segs = list(segments(y))
facts["segments"] = segs

# ---------- figure 6.1: sensor traces ----------
show = [("LIT101", "level LIT101 (stand-in units)"),
        ("AIT201", "analyser AIT201 (stand-in units)"),
        ("FIT101", "flow FIT101 (stand-in units)"),
        ("PIT501", "pressure PIT501 (stand-in units)")]
kinds = {11000: "offset\nFIT101", 13000: "stuck\nAIT201", 15000: "drift\nLIT101", 17000: "spike\nPIT501"}
fig, axes = plt.subplots(len(show), 1, figsize=(8, 7.5), sharex=True)
for ax, (c, lab), col in zip(axes, show, C):
    ax.plot(raw.index, raw[c], color=col, lw=0.5)
    for a, b in segs:
        ax.axvspan(a, b, color=ATTACK, alpha=0.18, lw=0)
    ax.set_ylabel(lab.split(" (")[0].replace(" ", "\n", 1) + "\n(synthetic units)", fontsize=10)
axes[0].set_title("Synthetic SWaT-format stand-in (ai/swat_like.csv) - not real plant data", fontsize=11)
for a, b in segs:
    axes[0].annotate(kinds[a], xy=((a + b) / 2, 1.0), xycoords=("data", "axes fraction"),
                     ha="center", va="bottom", fontsize=8.5, color=ATTACK)
axes[0].set_title("")
axes[-1].set_xlabel("row index (1 row = 1 s)")
from matplotlib.patches import Patch
axes[0].legend(handles=[Patch(color=ATTACK, alpha=0.3, label="labelled attack rows")],
                loc="upper left", frameon=False)
fig.subplots_adjust(hspace=0.25)
save(fig, "fig_swatlike.png")

# ---------- split ----------
first_atk = int(np.argmax(y == 1))
split = max(int(N * 0.5), first_atk)
Xtr = X[:split][y[:split] == 0]
Xte, yte = X[split:], y[split:]
facts.update(split_row=split, first_attack_row=first_atk, train_normal=len(Xtr),
             test_rows=len(Xte), test_attack_rows=int(yte.sum()),
             test_positive_rate=float(yte.mean()), always_normal_acc=float((yte == 0).mean()))

# ---------- figure 6.2: split timeline ----------
fig, ax = plt.subplots(figsize=(8, 2.9))
ax.barh(0, split, left=0, height=0.5, color=C[0], alpha=0.85, label=f"train (normal only): rows 0-{split-1}")
ax.barh(0, N - split, left=split, height=0.5, color=C[2], alpha=0.85, label=f"test: rows {split}-{N-1}")
for i, (a, b) in enumerate(segs):
    ax.barh(0, b - a, left=a, height=0.5, color=ATTACK, label="attack segment" if i == 0 else None)
    ax.text((a + b) / 2, 0.30 + 0.32 * (i % 2), f"{a}-{b-1}\n({b-a} rows)", ha="center", va="bottom", fontsize=8.5)
ax.axvline(split, color="black", lw=1.2, ls="--")
ax.text(split / 2, -0.06, f"train: {len(Xtr):,} normal rows", ha="center", va="center", color="white", fontsize=10.5)
ax.text(split + 150, -0.6, f"split = max(0.5 N, first attack) = {split:,}", ha="left", va="center", fontsize=9)
ax.text((split + N) / 2, -0.06, "", ha="center")
ax.set_ylim(-0.8, 1.3)
ax.set_yticks([])
ax.set_xlim(0, N)
ax.set_xlabel("row index (1 row = 1 s)")
ax.grid(False)
ax.spines["left"].set_visible(False)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.32), ncol=3, frameon=False, fontsize=9.5)
ax.set_title(f"test: {len(Xte):,} rows, {int(yte.sum()):,} attack rows in {len(segs)} segments", fontsize=10.5)
save(fig, "fig_split.png")

# ---------- figure 7.7: precision-recall curves ----------
scaler = StandardScaler().fit(Xtr)
Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)
scores = {}
iso = IsolationForest(n_estimators=200, random_state=0).fit(Xtr_s)
scores["Isolation Forest"] = -iso.score_samples(Xte_s)
rs = np.random.RandomState(0)
sub = Xtr_s[rs.choice(len(Xtr_s), min(len(Xtr_s), 8000), replace=False)]
oc = OneClassSVM(nu=0.05, gamma="scale").fit(sub)
scores["One-Class SVM"] = -oc.score_samples(Xte_s)
k = max(1, min(10, Xtr_s.shape[1] // 2))
pca = PCA(n_components=k).fit(Xtr_s)
scores["PCA reconstruction"] = np.mean((Xte_s - pca.inverse_transform(pca.transform(Xte_s))) ** 2, axis=1)
wtr = np.concatenate([windows(scaler.transform(X[a:b]), WINDOW) for a, b in normal_runs(y, split)])
ctx = max(0, split - WINDOW + 1)
wte = windows(scaler.transform(X[ctx:]), WINDOW)
model = train_ae(wtr, 0)
s_te = window_scores(model, wte)
assert len(s_te) == len(Xte_s)
scores["LSTM-AE (seed 0)"] = s_te
facts.update(pca_k=k, train_windows=len(wtr), test_windows=len(wte), ocsvm_subsample=len(sub))

fig, ax = plt.subplots(figsize=(8, 6))
aps = {}
for (name, s), col in zip(scores.items(), C):
    p, r, _ = precision_recall_curve(yte, s)
    ap = average_precision_score(yte, s)
    aps[name] = float(ap)
    ax.step(r, p, where="post", color=col, lw=1.8, label=f"{name}  (AP = {ap:.2f})")
base = yte.mean()
ax.axhline(base, color=GREY, ls="--", lw=1.2, label=f"no-skill baseline (positive rate = {base:.3f})")
ax.set_xlabel("recall")
ax.set_ylabel("precision")
ax.set_xlim(0, 1.0)
ax.set_ylim(0, 1.02)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=False)
ax.text(0.01, 0.01, f"synthetic stand-in test set: {len(yte):,} rows, {int(yte.sum()):,} attack rows",
        transform=ax.transAxes, fontsize=9, color=GREY)
save(fig, "fig_prcurves.png")
facts["average_precision"] = aps
print(json.dumps(facts, indent=1, default=str))
json.dump(facts, open(os.path.join(FIGS, "ml_facts.json"), "w"), indent=1, default=str)
