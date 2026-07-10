"""
profile_and_compare.py -- profile a device, then compare it to a REAL PLC.

This is the "profile the real, then mirror it" check: it fingerprints your decoy
the way an attacker would, and compares every trait to a real PLC's fingerprint
(from real_plc_reference.json). The gaps are exactly what makes your fake factory
look fake -- close them and it matches a real device.

  python profile_and_compare.py <host> <port> [label]
"""

import os
import sys
import json
import time

from pymodbus.client import ModbusTcpClient

HERE = os.path.dirname(os.path.abspath(__file__))
REF = json.load(open(os.path.join(HERE, "real_plc_reference.json")))

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5101
label = sys.argv[3] if len(sys.argv) > 3 else f"{host}:{port}"

client = ModbusTcpClient(host, port=port)
if not client.connect():
    print(f"cannot connect to {label}")
    raise SystemExit(1)


def supported(call):
    """True if a request works (the device supports that function code)."""
    try:
        return not call().isError()
    except Exception:
        return False


# --- fingerprint the device ---
profile = {}

try:
    di = client.read_device_information()
    profile["has_device_identity"] = (not di.isError()) and bool(getattr(di, "information", {}))
except Exception:
    profile["has_device_identity"] = False

profile["read_coils"] = supported(lambda: client.read_coils(0, count=1))
profile["read_discrete_inputs"] = supported(lambda: client.read_discrete_inputs(0, count=1))
profile["read_holding_registers"] = supported(lambda: client.read_holding_registers(0, count=1))
profile["read_input_registers"] = supported(lambda: client.read_input_registers(0, count=1))
profile["write_single_register"] = supported(lambda: client.write_register(0, 1))
profile["write_single_coil"] = supported(lambda: client.write_coil(0, False))
profile["rejects_bad_address"] = bool(client.read_holding_registers(9000, count=2).isError())

seen = set()
for _ in range(4):
    r = client.read_holding_registers(0, count=6)
    if not r.isError():
        seen.add(tuple(r.registers))
    time.sleep(1)
profile["values_change_over_time"] = len(seen) > 1

client.close()

# --- compare to the real device ---
print(f"\n=== {label}  vs  a REAL device ({REF['reference_device']}) ===")
want = REF["traits"]
match = 0
for trait, real_value in want.items():
    got = profile.get(trait, False)
    ok = (got == real_value)
    match += 1 if ok else 0
    print(f"  [{'MATCH' if ok else ' GAP '}] {trait:26} decoy={str(got):5}  real={real_value}")

pct = round(100 * match / len(want))
print(f"\n  looks like a real device: {match}/{len(want)} traits  ({pct}%)")
gaps = [t for t, v in want.items() if profile.get(t, False) != v]
if gaps:
    print("  gaps to close:", ", ".join(gaps))
