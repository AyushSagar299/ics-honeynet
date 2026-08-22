"""
tank_plc.py  --  Stage A of the ICS honeynet project.

This one program does two jobs at the same time, like a real PLC:
  1. it simulates a small water tank (the physics + the control logic), and
  2. it serves those values over Modbus TCP, so any Modbus client can read them.

Run it, then read it with read_test.py and you will see live, changing values.
Later (Stage B) the same values come from OpenPLC instead, but the Modbus
side stays exactly the same, so nothing after this needs to change.

The tank is a 1000 litre vessel with a fill pump, a heater and an outlet valve.
The physics is a bit more honest than a straight line: the outlet drains faster
when the tank is fuller (Torricelli), there is a daily demand cycle for the
water, and the temperature eases towards a target instead of jumping. Every
reading also gets a little sensor noise, because a real transmitter is never
exact. This all matters for the honeypot: a plant whose values are a clean
sawtooth is trivial to spot as fake, a plant that wobbles like real hardware is
not.

Register map -- HR0..HR5 are frozen (the bridge, twin and decoys depend on them):

  holding registers (read, and the setpoints are writable):
    HR0  water level      percent x10   (502 -> 50.2 %)
    HR1  temperature      deg C  x10    (585 -> 58.5 C)
    HR2  pressure         bar    x10
    HR3  pump             0 = off, 1 = on
    HR4  heater           0 = off, 1 = on
    HR5  valve            0 = closed, 1 = open
    HR6  inflow           litres/min x10
    HR7  outflow          litres/min x10
    HR8  stored volume    litres
    HR9  level setpoint low   percent x10   (writable)
    HR10 level setpoint high  percent x10   (writable)
    HR11 temp setpoint low    deg C  x10    (writable)
    HR12 temp setpoint high   deg C  x10    (writable)
    HR13 control mode     0 = auto, 1 = manual   (writable)
    HR14 alarm word       bitmask (see below)
    HR15 pump runtime     seconds (wraps at 65535)
    HR16 scan counter     +1 every scan (wraps) -- proves the plc is live
    HR17 ambient temp     deg C x10

  coils (read/write on/off -- this is the write surface an attacker can poke):
    CO0 pump command      (used in manual mode)
    CO1 heater command    (used in manual mode)
    CO2 valve command
    CO3 master run/enable
    CO4 alarm acknowledge (momentary)

  discrete inputs (read-only status):
    DI0 pump running   DI1 heater running   DI2 valve open
    DI3 high level     DI4 low level        DI5 high temp
    DI6 dry-run protect (near empty)        DI7 in auto mode

  input registers (read-only measurements, FC4): level, temp, pressure,
    inflow, outflow, ambient -- same x10 encoding as the holding registers.

  alarm word bits (HR14):
    bit0 high level   bit1 low level   bit2 high temp
    bit3 dry-run      bit4 low temp
"""

import os
import time
import math
import random
import threading

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusSlaveContext,
    ModbusServerContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartTcpServer

# Port 502 is the real Modbus port, but on a Mac that needs sudo, so for
# testing on the laptop we use 5020. In Docker we set MODBUS_PORT=502.
PORT = int(os.environ.get("MODBUS_PORT", "5020"))
TICK = 1.0          # seconds between physics steps
CAP_L = 1000.0      # the tank holds 1000 litres when full

# holding-register addresses (so the code below reads instead of magic numbers)
HR_LEVEL, HR_TEMP, HR_PRESS, HR_PUMP, HR_HEAT, HR_VALVE = 0, 1, 2, 3, 4, 5
HR_INFLOW, HR_OUTFLOW, HR_VOLUME = 6, 7, 8
HR_SP_LVL_LO, HR_SP_LVL_HI, HR_SP_T_LO, HR_SP_T_HI = 9, 10, 11, 12
HR_MODE, HR_ALARMS, HR_PUMP_SECS, HR_SCAN, HR_AMBIENT = 13, 14, 15, 16, 17

# coil addresses
CO_PUMP, CO_HEAT, CO_VALVE, CO_RUN, CO_ACK = 0, 1, 2, 3, 4

# the state of the tank in real-world units. we keep the physical truth here and
# add sensor noise only when we write it out, so the maths stays clean.
tank = {
    "volume": 500.0,   # litres in the tank right now (starts half full)
    "temp": float(os.environ.get("TANK_TEMP0", "22.0")),   # deg C
    "pump": 0,
    "heater": 0,
    "valve": 1,        # outlet valve, kept open so the tank always drains a bit
    "pump_secs": 0,    # how long the pump has run in total
    "scan": 0,         # scan counter
}

# the Modbus data store. we give it all four kinds of block (coils, discrete
# inputs, holding and input registers) so the device looks like a real PLC and
# not just a bag of holding registers.
store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [0] * 64),
    co=ModbusSequentialDataBlock(0, [0] * 64),
    hr=ModbusSequentialDataBlock(0, [0] * 100),
    ir=ModbusSequentialDataBlock(0, [0] * 64),
)
context = ModbusServerContext(slaves=store, single=True)


def clamp(x, lo, hi):
    return max(lo, min(hi, x))


def to_reg(x):
    # registers are unsigned 16-bit, so clamp before packing or pymodbus throws
    v = int(round(x))
    return max(0, min(65535, v))


def seed_defaults():
    # setpoints and the writable coils need sensible values before the first
    # scan reads them back
    store.setValues(3, HR_SP_LVL_LO, [400, 800, 550, 600])   # level 40/80 %, temp 55/60 C
    store.setValues(3, HR_MODE, [0])                          # start in auto
    store.setValues(1, CO_VALVE, [1])                         # valve open
    store.setValues(1, CO_RUN, [1])                           # running


def run_plant():
    """Move the tank one step, then copy the new values into the registers.
    This runs forever in a background thread."""
    while True:
        tank["scan"] = (tank["scan"] + 1) & 0xFFFF

        # 1. read the operator / attacker inputs back out of the registers, so a
        #    Modbus write to a setpoint or a coil actually changes the plant
        sp = store.getValues(3, HR_SP_LVL_LO, count=4)
        lvl_lo, lvl_hi = sp[0] / 10.0, sp[1] / 10.0
        t_lo, t_hi = sp[2] / 10.0, sp[3] / 10.0
        mode = store.getValues(3, HR_MODE, count=1)[0]        # 0 = auto, else manual
        c = store.getValues(1, 0, count=5)
        cmd_pump, cmd_heat, cmd_valve, running, ack = (int(v) for v in c)
        if ack:
            store.setValues(1, CO_ACK, [0])                   # acknowledge is momentary

        level = tank["volume"] / CAP_L * 100.0

        # ambient drifts over the day so the room is not perfectly constant
        day = (time.time() % 86400) / 86400.0
        ambient = 22.0 + 3.0 * math.sin(2 * math.pi * day)

        # 2. control rules -- what the PLC decides this scan
        if mode == 0:
            # auto: hysteresis control, keep level and temperature in their bands
            if level < lvl_lo:
                tank["pump"] = 1
            elif level > lvl_hi:
                tank["pump"] = 0
            if tank["temp"] < t_lo:
                tank["heater"] = 1
            elif tank["temp"] > t_hi:
                tank["heater"] = 0
            valve_open = 1
        else:
            # manual: obey the coils directly (the seize-control surface)
            tank["pump"] = 1 if cmd_pump else 0
            tank["heater"] = 1 if cmd_heat else 0
            valve_open = 1 if cmd_valve else 0

        if not running:                 # master run coil off -> stop everything
            tank["pump"] = 0
            tank["heater"] = 0

        # safety interlocks, these override the rules above like a real PLC
        dry = level < 8.0
        if dry:
            tank["heater"] = 0          # never fire the heater on a near-empty tank
        if level < 5.0:
            valve_open = 0              # shut the outlet so the tank cannot fully empty
        tank["valve"] = valve_open

        # 3. physics -- move the water and the heat by one second
        inflow = 12.0 if tank["pump"] else 0.0                 # litres/second in
        demand = 1.0 + 3.0 * (0.5 + 0.5 * math.sin(2 * math.pi * day))   # daily draw
        if tank["valve"]:
            drain = 0.7 * math.sqrt(max(level, 0.0))           # faster when fuller
            outflow = drain + demand
        else:
            outflow = 0.0
        tank["volume"] = clamp(tank["volume"] + (inflow - outflow) * TICK, 0.0, CAP_L)
        level = tank["volume"] / CAP_L * 100.0

        # first-order thermal: temperature eases towards a target, not a fixed step
        target = 65.0 if tank["heater"] else ambient
        tau = 25.0 if tank["heater"] else 60.0                 # heats faster than it cools
        tank["temp"] += (target - tank["temp"]) / tau * TICK
        tank["temp"] += random.gauss(0, 0.05)                  # process wobble
        tank["temp"] = clamp(tank["temp"], 10.0, 90.0)

        if tank["pump"]:
            tank["pump_secs"] = (tank["pump_secs"] + 1) & 0xFFFF

        # 4. sensor noise on the readings (a real transmitter is never exact).
        #    pressure is hydrostatic so it stays tied to the level -- the twin
        #    checks pressure == level*0.1, so keep the noise small.
        level_meas = clamp(level + random.gauss(0, 0.25), 0.0, 100.0)
        temp_meas = clamp(tank["temp"] + random.gauss(0, 0.08), 0.0, 100.0)
        press_meas = max(0.0, level_meas * 0.1 + random.gauss(0, 0.02))

        # 5. alarms
        alarms = 0
        if level_meas > 95:
            alarms |= 1 << 0
        if level_meas < 10:
            alarms |= 1 << 1
        if temp_meas > 70:
            alarms |= 1 << 2
        if dry:
            alarms |= 1 << 3
        if temp_meas < 40:
            alarms |= 1 << 4

        # 6. copy everything into the registers. x10 keeps one decimal place.
        #    write HR0..HR8 in one go, then HR14..HR17 -- this deliberately skips
        #    the writable setpoints (HR9..HR13) so an attacker's writes survive.
        store.setValues(3, HR_LEVEL, [
            to_reg(level_meas * 10),      # HR0
            to_reg(temp_meas * 10),       # HR1
            to_reg(press_meas * 10),      # HR2
            tank["pump"],                 # HR3
            tank["heater"],               # HR4
            tank["valve"],                # HR5
            to_reg(inflow * 60 * 10),     # HR6 inflow l/min x10
            to_reg(outflow * 60 * 10),    # HR7 outflow l/min x10
            to_reg(tank["volume"]),       # HR8 litres
        ])
        store.setValues(3, HR_ALARMS, [
            to_reg(alarms),               # HR14
            tank["pump_secs"],            # HR15
            tank["scan"],                 # HR16
            to_reg(ambient * 10),         # HR17
        ])

        # discrete input status bits (FC2)
        store.setValues(2, 0, [
            tank["pump"], tank["heater"], tank["valve"],
            1 if alarms & (1 << 0) else 0,
            1 if alarms & (1 << 1) else 0,
            1 if alarms & (1 << 2) else 0,
            1 if dry else 0,
            1 if mode == 0 else 0,
        ])

        # input registers mirror the live measurements (FC4)
        store.setValues(4, 0, [
            to_reg(level_meas * 10), to_reg(temp_meas * 10), to_reg(press_meas * 10),
            to_reg(inflow * 60 * 10), to_reg(outflow * 60 * 10), to_reg(ambient * 10),
        ])

        # flush=True so the line shows up right away in `docker compose logs`
        print(f"level={level_meas:5.1f}%  temp={temp_meas:4.1f}C  press={press_meas:4.2f}bar  "
              f"pump={tank['pump']}  heat={tank['heater']}  valve={tank['valve']}  "
              f"mode={'auto' if mode == 0 else 'man'}  alarms={alarms:05b}", flush=True)
        time.sleep(TICK)


if __name__ == "__main__":
    seed_defaults()

    # start the physics in the background...
    worker = threading.Thread(target=run_plant, daemon=True)
    worker.start()

    # a real PLC answers device-identification probes, so give it a plausible
    # Schneider Modicon identity instead of a blank one
    identity = ModbusDeviceIdentification()
    identity.VendorName = "Schneider Electric"
    identity.ProductCode = "BMXP34"
    identity.VendorUrl = "https://www.se.com"
    identity.ProductName = "Modicon M340"
    identity.ModelName = "BMXP342020"
    identity.MajorMinorRevision = "2.70"

    # ...then serve the registers over Modbus TCP (this call blocks forever)
    print(f"Water-tank PLC running.  Modbus TCP on port {PORT}.  Press Ctrl+C to stop.")
    StartTcpServer(context=context, identity=identity, address=("0.0.0.0", PORT))
