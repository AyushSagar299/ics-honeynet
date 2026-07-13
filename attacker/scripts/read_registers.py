"""
Scenario 2 -- Protocol enumeration.

Read the Modbus holding registers a few times. This is how an attacker learns
what the device is doing -- and, crucially, whether the values MOVE. A real
plant (and our live decoy) drifts over time; a fake honeypot stays frozen.
This is the test our whole project is about.

  python read_registers.py <host> <port>
"""

import sys
import time

from pymodbus.client import ModbusTcpClient

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5021

client = ModbusTcpClient(host, port=port)
if not client.connect():
    print(f"[enum] cannot connect to {host}:{port}")
    sys.exit(1)

print(f"[enum] reading registers 0..5 from {host}:{port}, three times (2s apart)")
seen = set()
for _ in range(3):
    r = client.read_holding_registers(0, count=6)
    if r.isError():
        print("        error:", r)
    else:
        regs = r.registers
        seen.add(tuple(regs))
        print(f"        level={regs[0] / 10:.1f}%  temp={regs[1] / 10:.1f}C  pump={regs[3]}")
    time.sleep(2)
client.close()

verdict = "LIVE (values move -- looks like a real plant)" if len(seen) > 1 else "STATIC (frozen -- gives itself away as fake)"
print(f"[enum] distinct readings: {len(seen)}  ->  {verdict}")
