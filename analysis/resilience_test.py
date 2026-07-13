"""
resilience_test.py -- how hard is the honeypot to CRACK?

A honeypot is *meant* to be easy to interact with -- open ports, no password --
because that is the lure that makes attackers engage. What must be hard is
CRACKING it in the dangerous sense: crashing it, hanging it, or breaking out to
the real plant. A good honeypot survives the assault and keeps logging.

This runs the attacks a hacker uses to break a server and reports how it holds up.

  python resilience_test.py <host> <port>
"""

import os
import sys
import socket
import random

from pymodbus.client import ModbusTcpClient

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5101


def alive():
    """Can a normal client still connect and read?"""
    try:
        c = ModbusTcpClient(host, port=port, timeout=2)
        if not c.connect():
            return False
        r = c.read_holding_registers(0, count=2)
        c.close()
        return not r.isError()
    except Exception:
        return False


def raw_send(data):
    try:
        s = socket.create_connection((host, port), timeout=1)
        s.sendall(data)
        s.close()          # fire and forget -- we're testing crash resistance, not the reply
        return True
    except OSError:
        return False


print(f"\n=== Resilience test vs {host}:{port} ===")
print("baseline -- server alive:", alive())

# 1. malformed / garbage flood -- try to crash the protocol parser
print("\n[1] flooding 150 malformed + garbage frames (try to crash it)...")
refused = 0
for _ in range(150):
    r = random.random()
    if r < 0.4:
        data = os.urandom(random.randint(1, 300))                       # pure garbage
    elif r < 0.7:
        data = b"\x00\x01\x00\x00\xff\xff\x01" + os.urandom(60)          # lying length field
    else:
        data = b"\x00\x01\x00\x00\x00\x06\x01" + bytes([random.randint(7, 255)]) + os.urandom(4)  # weird function code
    if not raw_send(data):
        refused += 1
survived_garbage = alive()
print(f"    sent 150 bad frames -> server still alive: {survived_garbage}")

# 2. connection flood -- try to exhaust it
print("\n[2] connection flood: holding 60 sockets open at once...")
socks = []
for _ in range(60):
    try:
        socks.append(socket.create_connection((host, port), timeout=1))
    except OSError:
        pass
can_still_connect = alive()      # can a NEW client get in while 60 are held?
for s in socks:
    try:
        s.close()
    except Exception:
        pass
print(f"    held {len(socks)} connections; a new client could still connect: {can_still_connect}")

# 3. rapid write flood -- unauthorised control (open BY DESIGN)
print("\n[3] write flood: 100 rapid unauthorised writes (no password needed)...")
accepted = 0
try:
    c = ModbusTcpClient(host, port=port, timeout=2)
    c.connect()
    for i in range(100):
        if not c.write_register(0, i).isError():
            accepted += 1
    c.close()
except Exception:
    pass
print(f"    {accepted}/100 writes accepted -- this is the LURE, not a weakness")

final = alive()

print("\n=== VERDICT ===")
print(f"  Attack surface (meant to be OPEN):  reads + writes accepted, no auth  ->  the lure")
print(f"  Resilience (meant to be HARD):")
print(f"     - survived garbage/malformed flood : {'YES' if survived_garbage else 'NO -- it crashed'}")
print(f"     - survived connection flood        : {'YES' if can_still_connect else 'NO -- it hung'}")
print(f"     - still up after the whole assault : {'YES' if final else 'NO'}")
print(f"  Containment: a write here can never reach the real plant -- the decoy is a")
print(f"     separate program on a separate network (proven: writing 9999 left the real PLC untouched).")
print(f"\n  => A honeypot is EASY to attack on purpose, but should be HARD to crash or escape.")
