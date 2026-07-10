"""
summarize_attacks.py -- read the honeypot logs and print a short attack report.

This is the light "logging analysis" path: no heavy ELK stack needed, just read
the JSON logs the decoys already write. It is also a preview of the JupyterLab
analysis you do in Month 4.

  python summarize_attacks.py <decoy.log> <hmi_attempts.log>
"""

import sys
import json
import collections


def load(path):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except FileNotFoundError:
        print(f"(no file: {path})")
    return rows


decoy_path = sys.argv[1] if len(sys.argv) > 1 else "decoy.log"
hmi_path = sys.argv[2] if len(sys.argv) > 2 else "hmi_attempts.log"

decoy = load(decoy_path)
hmi = load(hmi_path)

print("=== Modbus decoy activity ===")
print("total events:", len(decoy))
for kind, n in collections.Counter(r.get("event") for r in decoy).items():
    print(f"  {kind}: {n}")

writes = [r for r in decoy if r.get("event") == "write"]
if writes:
    print("unauthorised writes captured:")
    for w in writes:
        print(f"   {w.get('ts')}  fc={w.get('fc')}  addr={w.get('address')}  values={w.get('values')}")

print()
print("=== HMI login brute-force ===")
print("total attempts:", len(hmi))
if hmi:
    print("passwords tried:", dict(collections.Counter(r.get("password") for r in hmi)))
    print("source IPs:", dict(collections.Counter(r.get("ip") for r in hmi)))
