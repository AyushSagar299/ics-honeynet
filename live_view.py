"""
live_view.py -- watch a honeypot's values update live, in the terminal.

It connects to one honeypot over Modbus and re-reads its registers every second,
so you can SEE the values move. A real, running plant drifts all the time; a fake
static honeypot would sit frozen. This is the live behaviour my project adds.

  python live_view.py [host] [port]
  default: 127.0.0.1 5101  (the water-tank honeypot)

Press Ctrl+C to stop.
"""

import os
import sys
import time
from collections import deque

# Windows: enable ANSI colour/clear codes and UTF-8 output so the bars render
if os.name == "nt":
    os.system("")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from pymodbus.client import ModbusTcpClient

# read the fleet definition so we can label the registers for this port
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "honeynet", "fleet"))
try:
    from devices import DEVICES
except Exception:
    DEVICES = []

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5101

dev = next((d for d in DEVICES if d["public"] == port), None)
if dev:
    name = dev["name"]
    ident = f'{dev["id"]["vendor"]} {dev["id"]["model"]}'
    labels = [s[0] for s in dev["signals"]]
    # a fixed display range per signal (base +/- swing) so the bar is meaningful
    ranges = [(max(0, s[1] - s[2] * 1.4), s[1] + s[2] * 1.4) for s in dev["signals"]]
else:
    name, ident = f"device {host}:{port}", "unknown"
    labels, ranges = [f"reg{i}" for i in range(6)], None

SPARK = "▁▂▃▄▅▆▇█"


def spark(vals):
    lo, hi = min(vals), max(vals)
    rng = (hi - lo) or 1
    return "".join(SPARK[min(7, int((v - lo) / rng * 7.999))] for v in vals)


def bar(frac, width=24):
    frac = max(0.0, min(1.0, frac))
    fill = int(round(frac * width))
    return "█" * fill + "░" * (width - fill)


client = ModbusTcpClient(host, port=port)
if not client.connect():
    print(f"cannot connect to {host}:{port} -- is the honeypot running? (start it with ./demo.sh)")
    sys.exit(1)

history = {}
try:
    while True:
        r = client.read_holding_registers(0, count=len(labels))
        vals = [] if r.isError() else [x / 10.0 for x in r.registers]

        lines = [f"  {name}   *** LIVE ***   {host}:{port}",
                 f"  pretending to be a {ident}",
                 ""]
        for i, v in enumerate(vals):
            h = history.setdefault(i, deque(maxlen=40))
            h.append(v)
            if ranges:
                lo, hi = ranges[i]
                frac = (v - lo) / ((hi - lo) or 1)
            else:
                frac = 0.5
            lines.append(f"  {labels[i]:<14}{v:8.1f}   {bar(frac)}   {spark(h)}")
        lines += ["", "  the values keep moving -> it looks like a real, running plant",
                  "  (Ctrl+C to stop)"]

        sys.stdout.write("\033[2J\033[H" + "\n".join(lines) + "\n")
        sys.stdout.flush()
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    client.close()
