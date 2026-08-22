"""
generator.py -- background traffic, so the plant network is never silent.

A real plant network always has chatter: an HMI polling the PLC, a historian
sampling values, an engineer browsing the OPC UA tree, someone nudging a
setpoint. A network where NOBODY talks to the PLC until an attacker shows up
is its own tell, and the passive listener needs something to listen to. This
container plays the part of the operators:

  * polls the tank PLC over Modbus every few seconds, mixing the function
    codes like real clients do (holding registers mostly, coils and input
    registers now and then);
  * reads a couple of OPC UA nodes every ~10 s, browsed by name and not by a
    hard-coded numeric id, so it survives the server being rebuilt;
  * loads the HMI page like a bored operator glancing at the screen;
  * about every five minutes, moves a level setpoint a little, inside a safe
    band -- so the capture contains legitimate WRITES too, and a write alone
    is not what gives an attacker away.

Every timing is jittered. A client that polls at exactly 5.000 s forever is a
machine pretending to be a person.
"""

import os
import time
import random
import asyncio

import requests
from pymodbus.client import ModbusTcpClient
from asyncua import Client

PLC_HOST = os.environ.get("PLC_HOST", "10.10.0.10")
PLC_PORT = int(os.environ.get("PLC_PORT", "502"))
OPCUA_URL = os.environ.get("OPCUA_URL", "opc.tcp://10.10.0.12:4840/plant/")
HMI_URL = os.environ.get("HMI_URL", "http://10.10.0.13:5000")

HR_SP_LVL_LO, HR_SP_LVL_HI = 9, 10       # same frozen map as tank_plc.py


def poll_modbus():
    c = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=2)
    if not c.connect():
        raise OSError("no route to the PLC")
    r = c.read_holding_registers(0, count=18)
    # sometimes also touch the other function codes, like real clients do
    pick = random.random()
    if pick < 0.3:
        c.read_coils(0, count=5)
    elif pick < 0.5:
        c.read_input_registers(0, count=6)
    c.close()
    if r.isError():
        raise OSError("modbus read error")
    print(f"[modbus] level={r.registers[0] / 10:.1f}%  temp={r.registers[1] / 10:.1f}C", flush=True)


def nudge_setpoint():
    """The 'operator adjusts something' event: move one level setpoint a
    little, inside a band that can never hurt the plant (low stays 35-45,
    high stays 75-85, so low < high always holds)."""
    if random.random() < 0.5:
        hr, value, name = HR_SP_LVL_LO, random.uniform(35, 45), "low"
    else:
        hr, value, name = HR_SP_LVL_HI, random.uniform(75, 85), "high"
    c = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=2)
    if not c.connect():
        raise OSError("no route to the PLC")
    c.write_register(hr, int(round(value * 10)))
    c.close()
    print(f"[operator] level setpoint {name} -> {value:.1f}%", flush=True)


async def poll_opcua():
    async with Client(OPCUA_URL) as c:
        idx = await c.get_namespace_index("http://ics-lab.local")
        tank = await c.nodes.objects.get_child(f"{idx}:WaterTank")
        level = await (await tank.get_child(f"{idx}:Level")).read_value()
        temp = await (await tank.get_child(f"{idx}:Temperature")).read_value()
        print(f"[opc ua] level={level:.1f}%  temp={temp:.1f}C", flush=True)


def poll_hmi():
    requests.get(HMI_URL + "/", timeout=3)
    r = requests.get(HMI_URL + "/status", timeout=3)
    print(f"[hmi] status: {r.status_code}", flush=True)


print("background traffic generator started", flush=True)

now = time.time()
due = {
    "modbus": now,                                   # start polling right away
    "opcua": now + random.uniform(5, 10),
    "hmi": now + random.uniform(3, 8),
    "setpoint": now + random.uniform(120, 300),      # first nudge after a few minutes
}
tasks = {
    "modbus": (poll_modbus, 2, 6),
    "opcua": (lambda: asyncio.run(poll_opcua()), 8, 15),
    "hmi": (poll_hmi, 6, 20),
    "setpoint": (nudge_setpoint, 180, 420),
}

while True:
    now = time.time()
    for name, (fn, lo, hi) in tasks.items():
        if now < due[name]:
            continue
        try:
            fn()
        except Exception as e:
            # one dead service must not stop the chatter to the others
            print(f"[{name}] error: {e}", flush=True)
        due[name] = now + random.uniform(lo, hi)
    time.sleep(0.5)
