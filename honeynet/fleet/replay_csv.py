"""
replay_csv.py -- drive a Modbus honeypot from a real dataset (CSV).

Point it at a CSV of recorded sensor readings (rows from a real ICS dataset such
as SWaT, HAI, or the Morris SCADA sets) and it serves each row's values over
Modbus, one row per second, looping. This is how a REAL dataset plugs into the
project: the honeypot then shows values that actually came from a real plant,
instead of a live simulation.

  python replay_csv.py <dataset.csv> <port> [col1 col2 ...]

If you don't name columns, it uses the first few numeric columns it finds.
"""

import sys
import csv
import time
import threading

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer

if len(sys.argv) < 3:
    print(__doc__)
    raise SystemExit(0)

path = sys.argv[1]
port = int(sys.argv[2])
wanted = sys.argv[3:]


def is_number(x):
    try:
        float(x)
        return True
    except (TypeError, ValueError):
        return False


with open(path) as f:
    rows = list(csv.DictReader(f))
if not rows:
    print("dataset is empty")
    raise SystemExit(1)

# pick the columns to serve: the ones you named, or the first numeric ones
columns = wanted or [c for c in rows[0] if is_number(rows[0][c])][:6]
print("replaying columns:", columns)

store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0] * 100))
context = ModbusServerContext(slaves=store, single=True)


def player():
    """Walk through the dataset one row per second, into the registers."""
    i = 0
    while True:
        row = rows[i % len(rows)]
        regs = []
        for c in columns:
            try:
                regs.append(int(float(row[c]) * 10))     # x10, like the rest of the project
            except (KeyError, ValueError):
                regs.append(0)
        store.setValues(3, 0, regs)
        print(f"row {i % len(rows)}: {regs}", flush=True)
        i += 1
        time.sleep(1)


if __name__ == "__main__":
    threading.Thread(target=player, daemon=True).start()
    print(f"replaying {path} ({len(rows)} rows) over Modbus on port {port}. Ctrl+C to stop.", flush=True)
    StartTcpServer(context=context, address=("0.0.0.0", port))
