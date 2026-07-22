"""Self-contained animated decoy PLC for the Docker isolation demo.

It pretends to be a Schneider Modicon M340 and shows realistic, moving values
(a mean-reverting random walk, seeded from os.urandom so it cannot be curve-fit).
It is attacker-facing and lives on the isolated honeynet network, with no route
to the real plant.
"""
import os
import time
import random
import threading

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification

PORT = int(os.environ.get("MODBUS_PORT", "502"))
store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0] * 100))
context = ModbusServerContext(slaves=store, single=True)

ident = ModbusDeviceIdentification()
ident.VendorName = "Schneider Electric"
ident.ProductCode = "BMXP342020"
ident.ProductName = "Modicon M340"
ident.ModelName = "Modicon M340"
ident.MajorMinorRevision = "2.70"


def animate():
    rng = random.Random(os.urandom(16))
    level, temp, pressure = 60.0, 57.0, 6.0
    while True:
        level += 0.02 * (60 - level) + rng.gauss(0, 1.5)
        level = max(20.0, min(100.0, level))
        temp += 0.05 * (57 - temp) + rng.gauss(0, 0.1)
        pressure += 0.05 * (6 - pressure) + rng.gauss(0, 0.1)
        pump = 1 if level < 50 else 0
        store.setValues(3, 0, [int(level * 10), int(temp * 10), int(pressure * 10), pump])
        time.sleep(1)


threading.Thread(target=animate, daemon=True).start()
print(f"DECOY (fake Modicon M340) serving Modbus on port {PORT} -- attacker-facing honeynet", flush=True)
StartTcpServer(context=context, identity=ident, address=("0.0.0.0", PORT))
