"""
collect_data.py -- gather the measurement data for the thesis charts.

Run this while the pipeline + decoys are running (real PLC, bridge, twin, live
decoy, static decoy). It records two CSV files:

  fidelity.csv       -- real PLC level vs live-decoy level over time (the decoy
                        is fed by the twin, so this measures twin fidelity + lag)
  believability.csv  -- repeated reads of the live decoy vs the static decoy

The attacker logs (decoy.log, hmi.log) are produced separately by the attack run
and are read directly by analysis.py for the detection-coverage chart.
"""

import csv
import time

from pymodbus.client import ModbusTcpClient

REAL = ("127.0.0.1", 5020)
LIVE = ("127.0.0.1", 5021)
STATIC = ("127.0.0.1", 5022)


def connect(hostport):
    c = ModbusTcpClient(hostport[0], port=hostport[1])
    c.connect()
    return c


def level_temp(client):
    r = client.read_holding_registers(0, count=6)
    if r.isError():
        return None, None
    return r.registers[0] / 10, r.registers[1] / 10


real = connect(REAL)
live = connect(LIVE)
static = connect(STATIC)

# 1. fidelity: sample the real PLC and the live decoy every 0.5 s for 40 s
print("collecting fidelity for 40s ...")
with open("fidelity.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["t", "real_level", "decoy_level", "real_temp", "decoy_temp"])
    start = time.time()
    while time.time() - start < 40:
        t = time.time() - start
        rl, rt = level_temp(real)
        dl, dt = level_temp(live)
        if rl is not None and dl is not None:
            w.writerow([f"{t:.2f}", rl, dl, rt, dt])
        time.sleep(0.5)

# 2. believability: read the live and static decoys 12 times, 1.5 s apart
print("collecting believability ...")
with open("believability.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["read", "live_level", "static_level"])
    for i in range(12):
        ll, _ = level_temp(live)
        sl, _ = level_temp(static)
        w.writerow([i, ll, sl])
        time.sleep(1.5)

print("done: wrote fidelity.csv and believability.csv")
