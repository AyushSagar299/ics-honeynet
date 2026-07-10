"""
tank_plc.py  --  Stage A of the ICS honeynet project.

This one program does two jobs at the same time, like a real PLC:
  1. it simulates a small water tank (the physics), and
  2. it serves those values over Modbus TCP, so any Modbus client can read them.

Run it, then read it with read_test.py and you will see live, changing values.
Later (Stage B) the same values come from OpenPLC instead, but the Modbus
side stays exactly the same, so nothing after this needs to change.

Register map (holding registers):
  HR0 = water level   (percent x10 -> 502 means 50.2 %)
  HR1 = temperature   (deg C  x10 -> 235 means 23.5 C)
  HR2 = pressure      (bar    x10)
  HR3 = pump          (0 = off, 1 = on)
  HR4 = heater        (0 = off, 1 = on)
  HR5 = valve         (0 = closed, 1 = open)
"""

import os
import time
import random
import threading

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusSlaveContext,
    ModbusServerContext,
)
from pymodbus.server import StartTcpServer

# Port 502 is the real Modbus port, but on a Mac that needs sudo, so for
# testing on the laptop we use 5020. In Docker we set MODBUS_PORT=502.
PORT = int(os.environ.get("MODBUS_PORT", "5020"))
TICK = 1.0  # seconds between physics steps

# The state of the tank in real-world units. We keep it in one dict so it is
# easy to read and there are no global variables to worry about.
tank = {
    "level": 50.0,   # percent full
    "temp": 22.0,    # degrees C
    "pump": 0,       # inlet pump   0/1
    "heater": 0,     # heater       0/1
    "valve": 1,      # outlet valve 0/1 (kept open, so the tank always drains a bit)
}

# The Modbus data store: 100 holding registers, all starting at 0.
store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0] * 100))
context = ModbusServerContext(slaves=store, single=True)


def update_physics():
    """Move the tank one step, then copy the new values into the registers.
    This runs forever in a background thread."""
    while True:
        # 1. controller rules -- the logic a real PLC would run
        # keep the level between 40% and 80% by switching the pump on/off
        if tank["level"] < 40:
            tank["pump"] = 1
        elif tank["level"] > 80:
            tank["pump"] = 0
        # keep the water warm: heater on below 55 C, off above 60 C
        if tank["temp"] < 55:
            tank["heater"] = 1
        elif tank["temp"] > 60:
            tank["heater"] = 0

        # 2. physics -- how the tank changes in one tick
        if tank["pump"] == 1:
            tank["level"] += 1.0          # pump adds water
        if tank["valve"] == 1:
            tank["level"] -= 0.5          # open valve drains water
        tank["level"] = max(0.0, min(100.0, tank["level"]))

        if tank["heater"] == 1:
            tank["temp"] += 0.4           # heater warms the water
        else:
            tank["temp"] -= 0.2           # otherwise it cools toward the room
        tank["temp"] += random.uniform(-0.05, 0.05)   # tiny sensor noise
        tank["temp"] = max(18.0, min(80.0, tank["temp"]))

        pressure = tank["level"] * 0.1    # pressure just follows the level

        # 3. copy the values into the Modbus holding registers
        # registers are whole numbers, so we x10 to keep one decimal place
        registers = [
            int(tank["level"] * 10),      # HR0
            int(tank["temp"] * 10),       # HR1
            int(pressure * 10),           # HR2
            tank["pump"],                 # HR3
            tank["heater"],               # HR4
            tank["valve"],                # HR5
        ]
        context[0].setValues(3, 0, registers)   # 3 = holding registers, start at address 0

        # flush=True so the line shows up right away in `docker compose logs`
        print(f"level={tank['level']:5.1f}%  temp={tank['temp']:4.1f}C  "
              f"pump={tank['pump']}  heater={tank['heater']}", flush=True)
        time.sleep(TICK)


if __name__ == "__main__":
    # start the physics in the background...
    worker = threading.Thread(target=update_physics, daemon=True)
    worker.start()

    # ...then serve the registers over Modbus TCP (this call blocks forever)
    print(f"Water-tank PLC running.  Modbus TCP on port {PORT}.  Press Ctrl+C to stop.")
    StartTcpServer(context=context, address=("0.0.0.0", PORT))
