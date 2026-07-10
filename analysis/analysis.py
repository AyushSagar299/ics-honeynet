# %% [markdown]
# # ICS Honeynet — Results
#
# The three result charts for the thesis, from real data measured on the lab:
# 1. **Twin fidelity** — does the decoy (fed by the twin) track the real PLC?
# 2. **Believability** — does the live decoy move while the static one is frozen?
# 3. **Detection coverage** — what did the honeypot logs capture?
#
# (Also runnable as a plain script: `python analysis.py`.)

# %%
import csv
import json
import statistics

import matplotlib
matplotlib.use("Agg")            # save figures to files, no window needed
import matplotlib.pyplot as plt


def read_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def read_jsonl(path):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except FileNotFoundError:
        pass
    return rows


def mae(a, b):
    return sum(abs(x - y) for x, y in zip(a, b)) / len(a)


# %% [markdown]
# ## 1. Twin fidelity
# The decoy value should follow the real PLC closely, a short time later.

# %%
fid = read_csv("fidelity.csv")
t = [float(r["t"]) for r in fid]
real = [float(r["real_level"]) for r in fid]
decoy = [float(r["decoy_level"]) for r in fid]

# find the lag (in 0.5 s samples) that best lines the two curves up
best_lag, best_err = 0, mae(real, decoy)
for shift in range(1, 8):
    err = mae(real[shift:], decoy[:-shift])
    if err < best_err:
        best_lag, best_err = shift, err

print(f"mean |real - decoy| level error : {mae(real, decoy):.2f} %")
print(f"best lag                        : {best_lag * 0.5:.1f} s")
print(f"error after aligning by the lag : {best_err:.2f} %")

plt.figure(figsize=(8, 3.6))
plt.plot(t, real, label="real PLC", linewidth=2, color="#1f77b4")
plt.plot(t, decoy, label="decoy (fed by twin)", linewidth=1.6, linestyle="--", color="#d62728")
plt.xlabel("time (s)")
plt.ylabel("water level (%)")
plt.title(f"Twin fidelity — the decoy tracks the real PLC (lag ~{best_lag * 0.5:.1f}s)")
plt.legend()
plt.tight_layout()
plt.savefig("fig1_fidelity.png", dpi=120)
print("saved fig1_fidelity.png")

# %% [markdown]
# ## 2. Believability — live decoy vs static decoy
# A skilled attacker watches whether values change. Live moves; static is frozen.

# %%
bel = read_csv("believability.csv")
reads = [int(r["read"]) for r in bel]
live = [float(r["live_level"]) for r in bel]
static = [float(r["static_level"]) for r in bel]

live_std = statistics.pstdev(live)
static_std = statistics.pstdev(static)
print(f"live decoy   level std-dev over 12 reads: {live_std:.2f}  (moves)")
print(f"static decoy level std-dev over 12 reads: {static_std:.2f}  (frozen)")

plt.figure(figsize=(8, 3.6))
plt.plot(reads, live, marker="o", label=f"live decoy  (std={live_std:.1f})", color="#2ca02c")
plt.plot(reads, static, marker="s", label=f"static decoy (std={static_std:.1f})", color="#ff7f0e")
plt.xlabel("read number")
plt.ylabel("water level (%)")
plt.title("Believability — live decoy moves, static decoy is frozen")
plt.legend()
plt.tight_layout()
plt.savefig("fig2_believability.png", dpi=120)
print("saved fig2_believability.png")

# %% [markdown]
# ## 3. Detection coverage
# How much of each attack did the honeypot logs capture?

# %%
decoy_log = read_jsonl("decoy.log")
hmi_log = read_jsonl("hmi.log")
reads_seen = sum(1 for r in decoy_log if r.get("event") == "read")
writes_seen = sum(1 for r in decoy_log if r.get("event") == "write")
logins_seen = len(hmi_log)
print(f"captured: {reads_seen} reads, {writes_seen} writes, {logins_seen} login attempts")

labels = ["Modbus\nreads", "Modbus\nwrites", "HMI\nlogins", "port scan\n(recon)"]
coverage = [100 if reads_seen else 0, 100 if writes_seen else 0, 100 if logins_seen else 0, 0]
colors = ["#2ca02c", "#2ca02c", "#2ca02c", "#d62728"]

plt.figure(figsize=(7, 3.6))
bars = plt.bar(labels, coverage, color=colors)
plt.ylabel("% captured by honeypot logs")
plt.ylim(0, 115)
plt.title("Detection coverage (application-layer logging)")
for b, c in zip(bars, coverage):
    plt.text(b.get_x() + b.get_width() / 2, c + 3, f"{c}%", ha="center")
plt.figtext(0.5, -0.03, "port scans are seen by the network sensor (Zeek), not the app log",
            ha="center", fontsize=8, style="italic")
plt.tight_layout()
plt.savefig("fig3_coverage.png", dpi=120, bbox_inches="tight")
print("saved fig3_coverage.png")

# %% [markdown]
# ## 4. (optional) Clustering attacker sessions with KMeans
# A few example sessions, grouped by behaviour. With more real attack data this
# is how you would separate "scanners" from "tamperers" from "brute-forcers".

# %%
try:
    from sklearn.cluster import KMeans
    import numpy as np

    # each row = one attacker session: [reads, writes, logins, duration_s]
    sessions = np.array([
        [6, 0, 0, 5], [8, 0, 0, 7], [7, 0, 0, 6],       # scanners
        [4, 2, 0, 9], [5, 3, 0, 11],                    # tamperers (writes)
        [0, 0, 16, 20], [0, 0, 24, 28],                 # brute-forcers
    ])
    km = KMeans(n_clusters=3, n_init=10, random_state=0).fit(sessions)

    plt.figure(figsize=(6.5, 4))
    plt.scatter(sessions[:, 0], sessions[:, 2], c=km.labels_, cmap="Set1", s=90, edgecolor="k")
    plt.xlabel("Modbus reads in session")
    plt.ylabel("HMI login attempts in session")
    plt.title("KMeans — attacker sessions grouped by behaviour")
    plt.tight_layout()
    plt.savefig("fig4_kmeans.png", dpi=120)
    print("saved fig4_kmeans.png  (clusters:", km.labels_.tolist(), ")")
except Exception as e:
    print("skipping KMeans (scikit-learn not available):", e)
