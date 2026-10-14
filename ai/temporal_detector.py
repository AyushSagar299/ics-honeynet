"""
temporal_detector.py -- a TEMPORAL anomaly detector, to sit next to the
point-wise ones in swat_detector.py.

Isolation Forest, One-Class SVM and PCA all treat every timestamp as an
independent row. A water plant is a dynamical system though, so a lot of the
information is in HOW the sensors move together over time, not in any single
instant. An attacker who drifts a level slowly can stay inside the normal
per-instant distribution the whole time and still be obviously wrong as a
trajectory. So here I add one temporal model and put it in the same table.

I went with an LSTM autoencoder rather than a 1-D TCN. Both would work, but the
LSTM version is about fifteen lines of model code (encoder LSTM -> last hidden
state -> repeat -> decoder LSTM -> linear), it does not need me to pick a
dilation schedule or worry about the receptive field matching the window, and
it trained stably on the first try, so it is the easier one to defend. It is
deliberately small (one layer, 32 hidden units) -- this dataset is tiny and a
bigger net would just memorise it. CPU only, no GPU needed.

Anomaly score = mean squared reconstruction error of a whole window.

Same helpers, same metrics and same table as swat_detector.py, so the rows can
be read straight against each other.

  .venv/bin/python temporal_detector.py [path-to-csv]   (windows: .venv\\Scripts\\python.exe)
  (defaults to ai/swat_like.csv, same as swat_detector.py)
"""

import os
import sys
import time

import numpy as np
import torch
import torch.nn as nn
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from swat_detector import load, evaluate  # reuse the exact metrics/reporting

CSV = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "swat_like.csv")
WINDOW = 30         # 30 samples = 30 seconds of process history at 1 Hz
HIDDEN = 32
EPOCHS = 20
BATCH = 128
SEEDS = (0, 1, 2)   # torch + numpy seed, so the run is reproducible


def drop_counter_cols(X, cols):
    """drop columns that are just a row counter, not a sensor.

    the stand-in swat_like.csv has a numeric Timestamp column that only ever
    goes up. it is not a measurement, and because it never stops rising every
    test row sits outside the range the scaler saw in training, so it turns
    into a slow ramp that any model reads as "everything is getting weirder".
    that is unfair to all four models and it is especially bad for a window
    model. on the real SWaT file the timestamp is a date string and on HAI the
    time column is dropped by name, so in both of those cases this function
    finds nothing and changes nothing.
    swat_detector.py drops the counter the same way now, so the PCA rows in
    the two results files agree (0.56 on the stand-in).
    """
    keep = [i for i in range(X.shape[1]) if not np.all(np.diff(X[:, i]) > 0)]
    dropped = [cols[i] for i in range(X.shape[1]) if i not in keep]
    return X[:, keep], [cols[i] for i in keep], dropped


def normal_runs(y, end):
    # contiguous stretches of normal rows inside [0, end). i need the runs
    # rather than just "all rows where y==0" because a window has to be a real
    # unbroken piece of the process. if the training half had an attack in the
    # middle, stitching the two normal halves together would make a fake jump.
    runs, i = [], 0
    while i < end:
        if y[i] == 0:
            j = i
            while j < end and y[j] == 0:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    return runs


def windows(a, w):
    n = len(a) - w + 1
    if n <= 0:
        return np.zeros((0, w, a.shape[1]))
    return np.stack([a[i:i + w] for i in range(n)])


class SeqAE(nn.Module):
    """tiny lstm autoencoder: squash the window into one vector, then rebuild it."""

    def __init__(self, n_feat, hidden):
        super().__init__()
        self.enc = nn.LSTM(n_feat, hidden, batch_first=True)
        self.dec = nn.LSTM(hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, n_feat)

    def forward(self, x):
        _, (h, _) = self.enc(x)
        z = h[-1].unsqueeze(1).repeat(1, x.shape[1], 1)   # same code at every step
        d, _ = self.dec(z)
        return self.out(d)


def window_scores(model, w):
    # mse per window, in chunks so i never build a huge tensor
    model.eval()
    out = []
    with torch.no_grad():
        t = torch.tensor(w, dtype=torch.float32)
        for i in range(0, len(t), 512):
            b = t[i:i + 512]
            out.append(((model(b) - b) ** 2).mean(dim=(1, 2)).numpy())
    return np.concatenate(out) if out else np.zeros(0)


def train_ae(wtr, seed):
    torch.manual_seed(seed)
    np.random.seed(seed)
    model = SeqAE(wtr.shape[2], HIDDEN)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    lossf = nn.MSELoss()
    x = torch.tensor(wtr, dtype=torch.float32)
    model.train()
    for _ in range(EPOCHS):
        order = torch.randperm(len(x))
        for i in range(0, len(x), BATCH):
            b = x[order[i:i + BATCH]]
            opt.zero_grad()
            loss = lossf(model(b), b)
            loss.backward()
            opt.step()
    return model


def to_per_timestamp(win_score, n_rows):
    """fallback alignment, only used if the train half is shorter than one window.

    a window covering rows [i, i+WINDOW-1] is scored at its LAST timestamp,
    i+WINDOW-1, so at row t the detector has only used rows t-WINDOW+1 .. t.
    the first WINDOW-1 rows have no complete window of their own, and copying
    the first window's score onto them would mean scoring row 0 with samples
    that had not happened yet. i hit exactly that bug: the split lands on the
    first attack, so those rows were attack rows and it made the first
    detection look instant. main() now scores the test rows with windows that
    reach back into the train half instead (real past data), so this branch
    normally never runs. if it does, the rows are marked with the train-side
    minimum, which cannot flatter the model.
    """
    full = np.empty(n_rows)
    full[WINDOW - 1:] = win_score
    full[:WINDOW - 1] = win_score.min()
    return full


def main():
    if not os.path.exists(CSV):
        print("dataset not found:", CSV)
        print("generate the stand-in first: ", sys.executable, "make_swat_like.py")
        return
    t_start = time.time()

    X, y, cols = load(CSV)
    X, cols, dropped = drop_counter_cols(X, cols)

    # exactly the same temporal split as swat_detector.py: train is the earlier
    # part of the file, test is the later part. never shuffled, so the model
    # never sees the future.
    first_atk = int(np.argmax(y == 1)) if (y == 1).any() else len(y)
    split = max(int(len(y) * 0.5), first_atk)
    Xtr = X[:split][y[:split] == 0]                       # NORMAL only
    Xte, yte = X[split:], y[split:]
    scaler = StandardScaler().fit(Xtr)                    # fit on TRAIN only
    Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)

    # windows are built SEPARATELY inside train and inside test. no window is
    # allowed to straddle the split, because a window that started in train and
    # ended in test would be scored at test time by a model that had already
    # been trained on most of its own contents -- that is leakage and it would
    # quietly flatter the temporal model.
    wtr = np.concatenate([windows(scaler.transform(X[a:b]), WINDOW)
                          for a, b in normal_runs(y, split)])

    # scoring the test rows has to be causal as well. a window that ENDS at test
    # row t needs the WINDOW-1 rows before it, and for the first few test rows
    # those are the last rows of the train half. using them is allowed and it is
    # what really happens online: at time t the detector has already lived
    # through t-1, t-2 and so on. what it must never do is use rows AFTER t. so
    # i start the scoring windows WINDOW-1 rows early, and then every test row
    # has a full window of genuinely past samples and there is nothing to
    # backfill. the no-straddle rule above is about TRAINING windows, which is a
    # different thing: there the worry is the model being tested on its own
    # training data, here it is only reading past context it would really have.
    ctx = max(0, split - WINDOW + 1)
    wte = windows(scaler.transform(X[ctx:]), WINDOW)

    lines = []

    def out(s=""):
        print(s, flush=True)
        lines.append(s)

    out("=" * 82)
    out("  TEMPORAL ANOMALY DETECTION  (LSTM autoencoder vs the point-wise models)")
    out("=" * 82)
    out(f"  file: {os.path.basename(CSV)}   features: {len(cols)}   "
        f"train(normal): {len(Xtr)}   test: {len(Xte)}   attacks in test: {int(yte.sum())}")
    out(f"  window: {WINDOW} samples   hidden: {HIDDEN}   epochs: {EPOCHS}   "
        f"train windows: {len(wtr)}   test windows: {len(wte)}")
    if dropped:
        out(f"  dropped counter column(s): {', '.join(dropped)}  (row index, not a sensor)")
    out("-" * 82)
    out(f"  {'Model':20}{'PR-AUC':>8}{'F1':>8}{'F1adj':>8}{'Recall':>8}{'FA/day':>10}{'delay(s)':>10}  cover")

    # the point-wise baselines, on exactly the same rows and the same scaler
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
    pca_auc = average_precision_score(yte, te_err)

    # the temporal model, one row per seed so the spread is visible
    lstm_aucs = []
    for seed in SEEDS:
        model = train_ae(wtr, seed)
        s_tr = window_scores(model, wtr)          # threshold comes from these, TRAIN only
        s_te = window_scores(model, wte)          # already one score per test row
        if len(s_te) != len(Xte_s):               # only if train is shorter than a window
            s_te = to_per_timestamp(s_te, len(Xte_s))
        evaluate(f"LSTM-AE (seed {seed})", s_tr, s_te, yte, out)
        lstm_aucs.append(average_precision_score(yte, s_te))

    out("-" * 82)
    out(f"  LSTM-AE PR-AUC over {len(SEEDS)} seeds: mean {np.mean(lstm_aucs):.2f}, "
        f"range {min(lstm_aucs):.2f} to {max(lstm_aucs):.2f}   (PCA: {pca_auc:.2f})")
    out("=" * 82)
    out("  Same split, same scaler, same threshold rule (99.5th percentile of the TRAIN")
    out("  score) and the same evaluate() as swat_detector.py, so the rows are directly")
    out("  comparable. Training windows are built inside train only, so the model is")
    out("  never tested on its own training data. Each window is scored at its LAST")
    out("  timestamp and the scoring windows may reach back into the train half for")
    out("  context, so every test row is judged from past samples only, never future")
    out("  ones. The counter column was dropped first: it is a plain row index, and")
    out("  leaving it in turns into a ramp that flatters whichever model happens to")
    out("  key on it. swat_detector.py drops it too, so the PCA rows agree.")
    if np.mean(lstm_aucs) > pca_auc:
        out("  On this file the temporal model came out ahead of PCA on PR-AUC, which fits")
        out("  the argument: a slow drift and a stuck sensor look fine instant by instant")
        out("  and only stand out as a trajectory. It is not a clean sweep though -- read")
        out("  the delay column too, the window model needs a whole window of bad samples")
        out("  before the error builds up, so it is slower to fire than the point models.")
    else:
        out("  On this file the temporal model did NOT beat PCA. I am reporting that as the")
        out("  result rather than tuning it until it won -- the benchmark is close to")
        out("  saturated and a linear residual model is already a strong baseline on it.")
    out("  Either way the seed spread above is worth reading before claiming a winner: a")
    out("  gap smaller than the spread is not a real difference on this few attacks.")
    out("=" * 82)
    out(f"  runtime: {time.time() - t_start:.0f}s on cpu")

    with open(os.path.join(HERE, "temporal_results.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
