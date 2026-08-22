"""
read_test.py  --  a tiny Modbus client to check that tank_plc.py works.

It connects to the tank PLC and reads the registers three times, a moment
apart, so you can see the values changing. This is the same thing an
attacker (or your future bridge) does: just read the registers. It also
reads the coils, discrete inputs and input registers once at the end, to
show the device answers all four Modbus function codes like a real PLC.
"""

import os
import time

from pymodbus.client import ModbusTcpClient

PORT = int(os.environ.get("MODBUS_PORT", "5020"))


def read_once(client):
    # read HR0..HR17 (the whole map) in one request
    result = client.read_holding_registers(0, count=18)
    if result.isError():
        print("read error:", result)
        return
    r = result.registers
    mode = "auto" if r[13] == 0 else "manual"
    print(f"level={r[0] / 10:.1f}%  temp={r[1] / 10:.1f}C  pressure={r[2] / 10:.1f}bar  "
          f"pump={r[3]}  heater={r[4]}  valve={r[5]}  "
          f"inflow={r[6] / 10:.0f}  outflow={r[7] / 10:.0f} l/min  volume={r[8]}L  "
          f"mode={mode}  alarms={r[14]:05b}  scan={r[16]}")


client = ModbusTcpClient("127.0.0.1", port=PORT)

# the server may still be starting, so try to connect for a few seconds
for _ in range(10):
    if client.connect():
        break
    time.sleep(0.5)
else:
    print("could not connect to the tank PLC -- is tank_plc.py running?")
    raise SystemExit(1)

print("connected. reading the holding registers 3 times (1.5s apart):")
for _ in range(3):
    read_once(client)
    time.sleep(1.5)

# prove the other function codes work too, like a real device
coils = client.read_coils(0, count=5)
dis = client.read_discrete_inputs(0, count=8)
irs = client.read_input_registers(0, count=6)
if not coils.isError():
    print("coils (pump,heat,valve,run,ack):", coils.bits[:5])
if not dis.isError():
    print("status inputs (pump,heat,valve,hi,lo,hitemp,dry,auto):", dis.bits[:8])
if not irs.isError():
    print("input registers (level,temp,press,inflow,outflow,ambient):", irs.registers)

client.close()
