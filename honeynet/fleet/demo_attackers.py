"""
demo_attackers.py -- append EXAMPLE global attacker connections to the fleet log.

In the lab all real traffic is localhost, which has no map location. To show the
geolocation feature for the thesis, this writes example connections from public
IPs around the world, so the dashboard's country view has something to show.

These are clearly DEMO entries. Real captures (localhost, or real IPs on a
public/isolated network) still appear alongside them. To clear the demo data,
delete connections.log and restart the fleet.

  python demo_attackers.py [count]
"""

import os
import sys
import json
import random
from datetime import datetime, timedelta

from devices import DEVICES

HERE = os.path.dirname(os.path.abspath(__file__))
CONN_LOG = os.path.join(HERE, "connections.log")

# a spread of public IPs from different countries
IPS = ["8.8.8.8", "77.88.55.66", "202.108.22.5", "1.1.1.1", "200.160.2.3",
       "62.210.16.1", "185.220.101.1", "103.86.98.1", "41.204.16.1",
       "193.0.14.129", "45.153.160.2", "210.140.92.1"]

count = int(sys.argv[1]) if len(sys.argv) > 1 else 45
now = datetime.now()

lines = []
for _ in range(count):
    ip = random.choice(IPS)
    device = random.choice(DEVICES)
    ts = (now - timedelta(seconds=random.randint(0, 1200))).isoformat(timespec="seconds")
    lines.append({"ts": ts, "ip": ip, "port": random.randint(1024, 65000),
                  "honeypot": device["name"], "kind": device["kind"]})
lines.sort(key=lambda x: x["ts"])

with open(CONN_LOG, "a") as f:
    for line in lines:
        f.write(json.dumps(line) + "\n")

print(f"appended {count} demo attacker connections from {len(set(IPS))} public IPs")
