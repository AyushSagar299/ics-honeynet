"""
believability_test.py -- how convincing is a honeypot?

Fingerprint a device the way an attacker would, and score how "real" it looks.
Run it against your decoy and against a static honeypot to compare -- the gap is
the evidence for the project.

  python believability_test.py <host> <port> [label]
"""

import sys
import time

from pymodbus.client import ModbusTcpClient

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5021
label = sys.argv[3] if len(sys.argv) > 3 else f"{host}:{port}"

client = ModbusTcpClient(host, port=port)
if not client.connect():
    print(f"cannot connect to {label}")
    raise SystemExit(1)

checks = []

# 1. do the values change over time? (the biggest fingerprinting test)
seen = []
for _ in range(4):
    r = client.read_holding_registers(0, count=6)
    if not r.isError():
        seen.append(tuple(r.registers))
    time.sleep(1)
checks.append(("Values change over time (like a real plant)", len(set(seen)) > 1))

# 2. does it report a device identity? (real PLCs answer "who are you")
has_identity = False
try:
    di = client.read_device_information()
    has_identity = (not di.isError()) and bool(getattr(di, "information", {}))
except Exception:
    has_identity = False
checks.append(("Reports a device identity (vendor / product)", has_identity))

# 3. do the register values look plausible? (varied, not empty, not all 0xFFFF)
r = client.read_holding_registers(0, count=6)
regs = r.registers if not r.isError() else []
plausible = bool(regs) and len(set(regs)) > 1 and any(v > 0 for v in regs) and not all(v == 0xFFFF for v in regs)
checks.append(("Register values look plausible (varied, non-empty)", plausible))

# 4. does it reject a bad request like real firmware? (a proper Modbus error)
r = client.read_holding_registers(9000, count=2)     # out-of-range address
checks.append(("Rejects a bad request with a proper error", bool(r.isError())))

# 5. response timing (informational -- suspiciously instant hints "software")
t0 = time.time()
client.read_holding_registers(0, count=6)
ms = (time.time() - t0) * 1000
checks.append((f"Response time ~{ms:.1f} ms (plausible for a PLC)", 0.05 < ms < 500))

client.close()

score = sum(1 for _, ok in checks if ok)
print(f"\n=== Believability of {label} ===")
for name, ok in checks:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
print(f"  believability score: {score} / {len(checks)}")
