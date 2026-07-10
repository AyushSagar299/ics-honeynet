"""
read_test.py  --  a tiny Modbus client to check that tank_plc.py works.

It connects to the tank PLC and reads the registers three times, a moment
apart, so you can see the values changing. This is the same thing an
attacker (or your future bridge) does: just read the registers.
"""

import os
import time

from pymodbus.client import ModbusTcpClient

PORT = int(os.environ.get("MODBUS_PORT", "5020"))


def read_once(client):
    # read 6 holding registers starting at address 0 (HR0..HR5)
    result = client.read_holding_registers(0, count=6)
    if result.isError():
        print("read error:", result)
        return
    r = result.registers
    print(f"level={r[0] / 10:.1f}%  temp={r[1] / 10:.1f}C  pressure={r[2] / 10:.1f}bar  "
          f"pump={r[3]}  heater={r[4]}  valve={r[5]}")


client = ModbusTcpClient("127.0.0.1", port=PORT)

# the server may still be starting, so try to connect for a few seconds
for _ in range(10):
    if client.connect():
        break
    time.sleep(0.5)
else:
    print("could not connect to the tank PLC -- is tank_plc.py running?")
    raise SystemExit(1)

print("connected. reading 3 times (1.5s apart):")
for _ in range(3):
    read_once(client)
    time.sleep(1.5)

client.close()
