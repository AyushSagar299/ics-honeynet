# report figures 7.8, 7.2 and 7.4: the PR-AUC bars (read from the results files in
# ai/), the three fidelity re-runs (analysis/fidelity_reruns/) and the ten adversary
# bot runs. the bot scores are typed in below because the bot prints them, it
# does not save them.
#   .venv/bin/python analysis/report_figures/other_figs.py
import os, re, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from style import plt, save, C, GREY, ATTACK, REPO, FIGS
import numpy as np
import pandas as pd

facts = {}
AI = os.path.join(REPO, "ai")


def rows(fname):
    out = {}
    for line in open(os.path.join(AI, fname), encoding="utf-8"):
        m = re.match(r"\s{2}(\S.{0,19}?)\s+(\d\.\d\d)\s+\d\.\d\d\s+\d\.\d\d\s+\d\.\d\d\s+[\d.]+\s+\d+\s+\d/\d", line)
        if m:
            out[m.group(1).strip()] = float(m.group(2))
    return out


sw, tp, en, hai = rows("swat_results.txt"), rows("temporal_results.txt"), rows("ensemble_results.txt"), rows("hai_results.txt")
m = re.search(r"mean (\d\.\d\d), range (\d\.\d\d) to (\d\.\d\d)", open(os.path.join(AI, "temporal_results.txt")).read())
lstm_mean, lstm_lo, lstm_hi = map(float, m.groups())
facts["parsed"] = dict(swat=sw, temporal=tp, ensemble=en, hai=hai, lstm=(lstm_mean, lstm_lo, lstm_hi))

# ---------- figure 7.8: PR-AUC per model ----------
syn = [("Isolation Forest", sw["Isolation Forest"], None),
       ("One-Class SVM", sw["One-Class SVM"], None),
       ("PCA reconstruction", sw["PCA reconstruction"], None),
       ("LSTM-AE (mean of 3 seeds)", lstm_mean, (lstm_lo, lstm_hi)),
       ("Ensemble (avg + smoothing k=10)", en["Ensemble avg sm10"], None)]
real = [("Isolation Forest", hai["Isolation Forest"]),
        ("One-Class SVM", hai["One-Class SVM"]),
        ("PCA reconstruction", hai["PCA reconstruction"])]
fig, ax = plt.subplots(figsize=(8, 5))
ys_syn = np.arange(len(syn))[::-1] + len(real) + 1.2
ys_real = np.arange(len(real))[::-1]
for y0, (name, v, rng) in zip(ys_syn, syn):
    ax.barh(y0, v, height=0.6, color=C[0], label="synthetic SWaT-format stand-in" if y0 == ys_syn[0] else None)
    if rng:
        ax.errorbar(v, y0, xerr=[[v - rng[0]], [rng[1] - v]], fmt="none", ecolor="black", capsize=4, lw=1.2)
        ax.text(rng[1] + 0.015, y0, f"{v:.2f} (seeds {rng[0]:.2f}-{rng[1]:.2f})", va="center", fontsize=10)
    else:
        ax.text(v + 0.015, y0, f"{v:.2f}", va="center", fontsize=10)
for y0, (name, v) in zip(ys_real, real):
    ax.barh(y0, v, height=0.6, color=C[1], label="real HAI 21.03 data (reproduced 15 Oct 2026)" if y0 == ys_real[0] else None)
    ax.text(v + 0.015, y0, f"{v:.2f}", va="center", fontsize=10)
ax.axhline(len(real) + 0.1, color=GREY, lw=0.8, ls=":")
ax.set_yticks(list(ys_syn) + list(ys_real))
ax.set_yticklabels([s[0] for s in syn] + [r[0] for r in real])
ax.set_xlim(0, 1)
ax.set_xlabel("PR-AUC (average precision)")
ax.grid(axis="y", visible=False)
ax.legend(loc="lower right", frameon=False)
save(fig, "fig_mlbar.png")

# ---------- figure 7.2: fidelity re-runs of 15 October 2026 ----------
FID = os.path.join(REPO, "analysis", "fidelity_reruns")
fig, axes = plt.subplots(1, 3, figsize=(8.5, 3.4), sharey=False)
fr = []
for i, ax in enumerate(axes, 1):
    d = pd.read_csv(os.path.join(FID, f"fid_run{i}.csv"))
    err = (d.real_level - d.decoy_level).abs()
    mae = err.mean()
    lags = {}
    for k in range(-6, 7):
        a, b = d.real_level.to_numpy(), d.decoy_level.to_numpy()
        if k >= 0:
            lags[k] = np.abs(a[:len(a) - k] - b[k:]).mean()
        else:
            lags[k] = np.abs(a[-k:] - b[:len(b) + k]).mean()
    best = min(lags, key=lags.get)
    dt = float(np.median(np.diff(d.t)))
    r = dict(run=i, n=len(d), duration_s=float(d.t.iloc[-1]), median_dt=dt, mae_pp=float(mae),
             mismatches=int((err > 1e-9).sum()), max_abs_err=float(err.max()),
             mean_level=float(d.real_level.mean()), rel_mae_pct=float(100 * mae / d.real_level.mean()),
             best_lag_samples=best, best_lag_s=best * dt)
    fr.append(r)
    ax.plot(d.t, d.real_level, color=C[0], lw=2.2, label="real plant (tank_plc.py)")
    ax.plot(d.t, d.decoy_level, color=C[1], lw=1.2, ls="--", label="live decoy")
    ax.set_title(f"Run {i}: MAE = {mae:.3f} pp", fontsize=11)
    ax.set_xlabel("time (s)")
axes[0].set_ylabel("tank level (%)")
axes[0].legend(loc="upper center", bbox_to_anchor=(1.7, -0.25), ncol=2, frameon=False)
fig.subplots_adjust(wspace=0.35)
save(fig, "fig_fidelity_runs.png")
facts["fidelity"] = fr

# ---------- figure 7.4: adversary bot, ten runs (6 on current code, 4 on the previous commit) ----------
scores = [83, 85, 82, 89, 83, 80, 95, 84, 79, 76]
cur = list(range(6))
fig, ax = plt.subplots(figsize=(8, 4))
x = np.arange(1, 11)
ax.plot(x[:6], scores[:6], "o", ms=9, color=C[0], label="current code (6 runs)")
ax.plot(x[6:], scores[6:], "s", ms=9, mfc="white", mec=C[1], mew=2, label="previous commit (4 runs)")
for xi, s in zip(x, scores):
    ax.text(xi, s + 1.2, str(s), ha="center", fontsize=9.5)
med = float(np.median(scores))
ax.axhline(med, color=GREY, ls="--", lw=1.2)
ax.text(10.45, med - 1.2, f"median {med:.0f}", va="center", fontsize=9.5, color=GREY)
ax.axhline(85, color=ATTACK, ls=":", lw=1.4)
ax.text(10.45, 86.2, "grade A\n(overall >= 85)", va="center", fontsize=9.5, color=ATTACK)
ax.axvline(6.5, color="#c9c8c3", lw=1)
ax.set_xticks(x)
ax.set_xlim(0.5, 10.4)
ax.set_ylim(70, 100)
ax.set_xlabel("run number (in the order the runs were made)")
ax.set_ylabel("overall bot score (/100)")
ax.legend(loc="upper left", frameon=False)
save(fig, "fig_bot_runs.png")
facts["bot"] = dict(scores=scores, median=med, min=min(scores), max=max(scores),
                    n_ge_85=sum(s >= 85 for s in scores), n_gt_85=sum(s > 85 for s in scores))
print(json.dumps(facts, indent=1))
json.dump(facts, open(os.path.join(FIGS, "other_facts.json"), "w"), indent=1)
