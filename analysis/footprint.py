"""
footprint.py -- measure how much memory and CPU the running honeynet uses.

I used to quote "about 113 MB" from watching Activity Monitor, which is not
something anyone can repeat. This script measures it the same way every time:
start the demo, wait for it to settle, then run

  .venv/bin/python analysis/footprint.py            (default: 10 samples, 2 s apart)
  .venv/bin/python analysis/footprint.py 30 1

It finds the honeynet's own python processes by their script names, adds up
their resident memory (RSS) and CPU with ps, and prints the median over the
samples. RSS counts shared libraries once per process, so the total is a bit
higher than the real unique memory -- it is an upper bound, not an exact figure.
"""

import os
import sys
import time
import statistics
import subprocess

# the demo's processes, matched on the script name in their command line
SCRIPTS = ["run_fleet.py", "decoy_opcua.py", "static_decoy.py", "decoy_hmi.py", "dashboard.py"]

samples = int(sys.argv[1]) if len(sys.argv) > 1 else 10
gap = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0


def snapshot():
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,rss=,%cpu=,command="], capture_output=True, text=True).stdout
    procs = {}
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) == 5:
            procs[int(parts[0])] = (int(parts[1]), int(parts[2]), float(parts[3]), parts[4])
    # which script does each process belong to? the fleet starts its 8 backends as
    # multiprocessing children whose command line does not say run_fleet.py, so a
    # process also counts for a script if one of its parents does
    def owner(pid, depth=0):
        if pid not in procs or depth > 5:
            return None
        cmd = procs[pid][3]
        if "python" in cmd.lower():
            for s in SCRIPTS:
                if s in cmd:
                    return s
        return owner(procs[pid][0], depth + 1)
    per = {s: [0, 0.0, 0] for s in SCRIPTS}          # rss kB, cpu %, process count
    for pid, (ppid, rss, cpu, cmd) in procs.items():
        s = owner(pid)
        if s and "python" in cmd.lower():
            per[s][0] += rss; per[s][1] += cpu; per[s][2] += 1
    return per


runs = []
for i in range(samples):
    runs.append(snapshot())
    if i < samples - 1:
        time.sleep(gap)

if sum(r[s][2] for r in runs for s in SCRIPTS) == 0:
    print("no honeynet processes found -- start the demo first (./demo.sh)")
    sys.exit(1)

print(f"honeynet footprint, median of {samples} samples {gap:g} s apart")
print(f"  {'process':18}{'count':>6}{'RSS (MB)':>10}{'CPU %':>8}")
tot_mb, tot_cpu = [], []
for s in SCRIPTS:
    mb = statistics.median(r[s][0] / 1024 for r in runs)
    cpu = statistics.median(r[s][1] for r in runs)
    n = max(r[s][2] for r in runs)
    print(f"  {s:18}{n:>6}{mb:>10.1f}{cpu:>8.1f}")
for r in runs:
    tot_mb.append(sum(r[s][0] for s in SCRIPTS) / 1024)
    tot_cpu.append(sum(r[s][1] for s in SCRIPTS))
print(f"  {'TOTAL':18}{'':>6}{statistics.median(tot_mb):>10.1f}{statistics.median(tot_cpu):>8.1f}")
print(f"  total RSS range over the samples: {min(tot_mb):.1f} - {max(tot_mb):.1f} MB")
print("  (RSS is an upper bound: shared libraries are counted once per process)")
