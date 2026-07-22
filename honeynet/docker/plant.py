"""Self-contained 'real OT plant' for the Docker isolation demo (a water tank)."""
import os
import time
import random
import threading

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer

PORT = int(os.environ.get("MODBUS_PORT", "502"))
store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0] * 100))
context = ModbusServerContext(slaves=store, single=True)


def physics():
    level, temp, pump, heater, valve = 50.0, 57.0, 0, 0, 1
    while True:
        if level < 40:
            pump = 1
        elif level > 80:
            pump = 0
        if temp < 55:
            heater = 1
        elif temp > 60:
            heater = 0
        if pump:
            level += 1.0
        if valve:
            level -= 0.5
        level = max(0.0, min(100.0, level))
        temp += (0.4 if heater else -0.2) + random.uniform(-0.05, 0.05)
        pressure = level * 0.1
        store.setValues(3, 0, [int(level * 10), int(temp * 10), int(pressure * 10), pump, heater, valve])
        time.sleep(1)


threading.Thread(target=physics, daemon=True).start()
print(f"PLANT (real OT) serving Modbus on port {PORT} -- isolated OT network", flush=True)
StartTcpServer(context=context, address=("0.0.0.0", PORT))
