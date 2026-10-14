"""
static_decoy.py -- a plain STATIC Modbus honeypot (the baseline to beat).

This is what an ordinary honeypot looks like: it serves fixed values that never
change. It uses the SAME register map as our live decoy, so the comparison is
fair -- under the same attack, the live decoy's values drift like a real plant,
while this one's values are frozen. A skilled attacker reads a few registers,
sees nothing ever moves, and knows within minutes it is a trap.

This is the control we measure the live decoy against in the project.
"""

import os

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer

PORT = int(os.environ.get("MODBUS_PORT", "5022"))

# a frozen snapshot of a tank -- level 50.0%, temp 23.5C, pressure 5.0, all on.
# (same x10 encoding and register order as the real PLC and the live decoy)
FIXED = [500, 235, 50, 1, 1, 1]

store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0] * 100))
context = ModbusServerContext(slaves=store, single=True)
# write the fixed values the same way the real PLC does, so the register
# addresses line up exactly (setValues at address 0 == what a client reads at 0)
store.setValues(3, 0, FIXED)

if __name__ == "__main__":
    print(f"STATIC Modbus honeypot on port {PORT}. Values never change.", flush=True)
    StartTcpServer(context=context, address=(os.environ.get("FLEET_BIND", "0.0.0.0"), PORT))
