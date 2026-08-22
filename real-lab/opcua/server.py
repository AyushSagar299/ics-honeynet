"""
server.py -- the plant's OPC UA face (a Modbus -> OPC UA gateway).

A real site rarely speaks only Modbus: there is usually an OPC UA server on
top, in the PLC itself or in a small gateway box, and that is what the
SCADA/MES layer talks to. This container is that box for our water plant. It
reads the tank PLC's registers over Modbus once a second and republishes them
as a proper node tree, so both protocols tell the same live story.

(The old version of this file served two hard-coded values that never moved --
exactly the frozen-honeypot tell this whole project is about, sitting in our
own "real" lab.)

What a client sees when it browses:

  Objects/
    WaterTank/
      Level, Temperature, Pressure      floats (the x10 registers, divided back)
      Pump, Heater, Valve               booleans
      Inflow, Outflow, Volume           floats
      Setpoints/
        LevelLow, LevelHigh             floats, WRITABLE

The two setpoints are the only writable nodes, and a write really lands in the
PLC (HR9/HR10), so OPC UA is a second genuine control path, not just a viewer.
The PLC stays the single source of truth: every tick we push its values into
the nodes, and a setpoint node that no longer matches what we pushed means an
OPC UA client wrote it, so we forward that to the PLC.
"""

import os
import asyncio

from asyncua import Server
from pymodbus.client import ModbusTcpClient

PLC_HOST = os.environ.get("PLC_HOST", "10.10.0.10")
PLC_PORT = int(os.environ.get("PLC_PORT", "502"))
OPCUA_PORT = int(os.environ.get("OPCUA_PORT", "4840"))
TICK = 1.0

# same frozen register map as tank_plc.py -- HR0..HR8 values, HR9/HR10 setpoints
HR_SP_LVL_LO, HR_SP_LVL_HI = 9, 10


def read_plc(plc):
    """One Modbus read of HR0..HR10. Returns None when the PLC is not there yet
    (the containers race at startup, so the gateway just keeps trying)."""
    if not plc.connect():
        return None
    r = plc.read_holding_registers(0, count=11)
    if r.isError():
        return None
    return r.registers


async def main():
    server = Server()
    await server.init()
    server.set_server_name("water-plant OPC UA gateway")
    server.set_endpoint(f"opc.tcp://0.0.0.0:{OPCUA_PORT}/plant/")
    idx = await server.register_namespace("http://ics-lab.local")

    tank = await server.nodes.objects.add_object(idx, "WaterTank")
    level = await tank.add_variable(idx, "Level", 0.0)
    temp = await tank.add_variable(idx, "Temperature", 0.0)
    press = await tank.add_variable(idx, "Pressure", 0.0)
    pump = await tank.add_variable(idx, "Pump", False)
    heater = await tank.add_variable(idx, "Heater", False)
    valve = await tank.add_variable(idx, "Valve", False)
    inflow = await tank.add_variable(idx, "Inflow", 0.0)
    outflow = await tank.add_variable(idx, "Outflow", 0.0)
    volume = await tank.add_variable(idx, "Volume", 0.0)

    sps = await tank.add_object(idx, "Setpoints")
    sp_nodes = {
        HR_SP_LVL_LO: await sps.add_variable(idx, "LevelLow", 40.0),
        HR_SP_LVL_HI: await sps.add_variable(idx, "LevelHigh", 80.0),
    }
    for node in sp_nodes.values():
        await node.set_writable()

    plc = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=2)
    pushed = {}     # hr address -> the setpoint value we last pushed to the node

    print(f"OPC UA gateway on port {OPCUA_PORT}, mirroring Modbus {PLC_HOST}:{PLC_PORT}", flush=True)
    async with server:
        while True:
            # the pymodbus client is blocking, so read it in a worker thread and
            # keep the OPC UA server responsive while we wait
            regs = await asyncio.to_thread(read_plc, plc)
            if regs is None:
                print("cannot reach the PLC, retrying...", flush=True)
                await asyncio.sleep(TICK)
                continue

            await level.write_value(regs[0] / 10.0)
            await temp.write_value(regs[1] / 10.0)
            await press.write_value(regs[2] / 10.0)
            await pump.write_value(bool(regs[3]))
            await heater.write_value(bool(regs[4]))
            await valve.write_value(bool(regs[5]))
            await inflow.write_value(regs[6] / 10.0)
            await outflow.write_value(regs[7] / 10.0)
            await volume.write_value(float(regs[8]))

            for hr, node in sp_nodes.items():
                cur = await node.read_value()
                if hr in pushed and abs(cur - pushed[hr]) > 0.01:
                    # the node moved since we last pushed it = a client wrote it.
                    # forward to the PLC and let the PLC's value come back to us
                    # on the next tick, so the PLC stays the boss.
                    await asyncio.to_thread(plc.write_register, hr, int(round(cur * 10)))
                    pushed[hr] = cur
                    print(f"setpoint write from OPC UA: HR{hr} <- {cur:.1f}", flush=True)
                else:
                    await node.write_value(regs[hr] / 10.0)
                    pushed[hr] = regs[hr] / 10.0

            await asyncio.sleep(TICK)


if __name__ == "__main__":
    asyncio.run(main())
