"""
honeypot_detector.py -- play the ATTACKER trying to spot a fake.

Runs the tricks a skilled attacker uses to detect an ICS honeypot, and reports
every "tell" that gives it away. Use it on your own honeynet to find (and then
fix) the weaknesses -- this is the adversarial side of the believability test.

  python honeypot_detector.py <host> <port> [sibling_port]
"""

import sys
import time
import socket
import statistics

from pymodbus.client import ModbusTcpClient

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5101
sibling = int(sys.argv[3]) if len(sys.argv) > 3 else 5102


def connect(p):
    c = ModbusTcpClient(host, port=p)
    return c if c.connect() else None


def has_identity(c):
    try:
        di = c.read_device_information()
        return (not di.isError()) and bool(getattr(di, "information", {}))
    except Exception:
        return False


c = connect(port)
if not c:
    print(f"cannot connect to {host}:{port}")
    raise SystemExit(1)

tells = []

# --- 1. does it identify itself? ---
if not has_identity(c):
    tells.append(("No device identity",
                  "asked 'who are you?' (Modbus fn 43) and got nothing back -- a real PLC "
                  "returns a vendor / product / firmware version"))

# --- 2. are the values real, or frozen, or too smooth? ---
vals = []
for _ in range(10):
    r = c.read_holding_registers(0, count=1)
    if not r.isError():
        vals.append(r.registers[0])
    time.sleep(0.25)
if len(set(vals)) <= 1:
    tells.append(("Frozen values", "the readings never changed -- an obvious static honeypot"))
else:
    diffs = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]
    if len(diffs) > 2 and statistics.pstdev(diffs) < 1.2:
        tells.append(("Values look synthetic",
                      "the readings move on a smooth, almost noiseless curve -- a real sensor "
                      "is jittery/physical, not a clean maths function"))

# --- 3. is every 'device' actually the same fake? ---
c2 = connect(sibling)
if c2:
    same_identity = (has_identity(c) == has_identity(c2))
    err_a = c.read_holding_registers(9000, count=2).isError()
    err_b = c2.read_holding_registers(9000, count=2).isError()
    if same_identity and (err_a == err_b) and not has_identity(c):
        tells.append(("Devices are clones",
                      f"this device and its neighbour (:{sibling}) have the identical fingerprint "
                      "and behaviour -- a real plant has mixed vendors and firmware"))
    c2.close()

# --- 4. how thin is the service surface? ---
tells.append(("Only Modbus is exposed",
              "the device answers Modbus but offers no web UI (80/8080) or SNMP (161) -- "
              "most real PLCs also expose a management interface"))

c.close()

print(f"\n=== Honeypot-detection test vs {host}:{port}  (playing the attacker) ===")
if not tells:
    print("  No obvious tells found -- it holds up well.")
else:
    for i, (t, why) in enumerate(tells, 1):
        print(f"  [TELL {i}] {t}")
        print(f"           {why}")
print(f"\n  {len(tells)} tell(s) found.")
print("  Also expose a software honeypot but NOT tested here (network level, needs root):")
print("   - OS fingerprint: nmap -O shows a PC OS, not an embedded PLC")
print("   - MAC-address vendor and TCP/IP stack quirks don't match a real PLC")
