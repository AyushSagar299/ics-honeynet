"""
server.py -- the plant's S7 face (a Modbus -> S7comm mirror).

The 4SICS capture we analysed is dominated by real S7 traffic, so a plant
network with no S7 device on it looks thin. This container puts the water tank
behind S7comm as well: it reads the tank PLC over Modbus once a second and
serves the same values as data block DB1, the way a Siemens PLC would. (The
old version served a DB full of zeros that never changed -- the classic
frozen-honeypot tell.)

DB1 layout -- big-endian 16-bit words, same x10 encoding as the Modbus map:

  DBW0  level    percent x10       DBW12 inflow  l/min x10
  DBW2  temp     deg C x10         DBW14 outflow l/min x10
  DBW4  pressure bar x10           DBW16 volume  litres
  DBW6  pump     0/1               DBW18 alarm word (same bits as HR14)
  DBW8  heater   0/1               DBW20 scan counter
  DBW10 valve    0/1

Anyone can also WRITE into DB1 (no authentication, true to the protocol), but
the mirror refreshes from the PLC every second, so a write only sticks until
the next tick. python-snap7 3.x ships a pure-Python server, so the container
needs no native snap7 library.
"""

import os
import time
import struct

from pymodbus.client import ModbusTcpClient
from snap7.server import Server
from snap7.type import SrvArea

PLC_HOST = os.environ.get("PLC_HOST", "10.10.0.10")
PLC_PORT = int(os.environ.get("PLC_PORT", "502"))
S7_PORT = int(os.environ.get("S7_PORT", "102"))
TICK = 1.0

# registered as a bytearray on purpose: the server keeps a reference to a
# bytearray (a ctypes array would get copied), so packing new values into it
# is a live update that every connected client sees
db1 = bytearray(200)

server = Server()
server.register_area(SrvArea.DB, 1, db1)
server.start(tcp_port=S7_PORT)
print(f"S7 mirror on port {S7_PORT} (DB1), reading Modbus {PLC_HOST}:{PLC_PORT}", flush=True)

plc = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=2)
while True:
    ok = False
    if plc.connect():
        r = plc.read_holding_registers(0, count=18)
        if not r.isError():
            g = r.registers
            # lock while packing so a client never reads a half-updated block
            server.lock_area(SrvArea.DB, 1)
            struct.pack_into(">11H", db1, 0,
                             g[0], g[1], g[2],        # level, temp, pressure
                             g[3], g[4], g[5],        # pump, heater, valve
                             g[6], g[7], g[8],        # inflow, outflow, volume
                             g[14], g[16])            # alarms, scan counter
            server.unlock_area(SrvArea.DB, 1)
            ok = True
    if not ok:
        print("cannot reach the PLC, retrying...", flush=True)
    time.sleep(TICK)
