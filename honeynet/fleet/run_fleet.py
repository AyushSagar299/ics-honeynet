"""
run_fleet.py -- start the whole honeypot fleet.

For every device in devices.py it starts two things:
  * a BACKEND -- a Modbus decoy that simulates that device's values and logs
    every read/write (bound to 127.0.0.1 only, so attackers can't reach it
    directly);
  * a SENSOR -- a tiny relay on the public port that logs the attacker's real
    source IP the moment they connect, then forwards their traffic to the
    backend.

So the honeynet looks like a whole plant of equipment, and every connection is
tagged with a real source IP. Writes:
  connections.log -- one line per attacker connection (ip, honeypot)
  actions.log     -- one line per read/write (honeypot, what they did)
"""

import os
import json
import math
import time
import random
import asyncio
import threading
import multiprocessing
from datetime import datetime

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification

from devices import DEVICES

HERE = os.path.dirname(os.path.abspath(__file__))
CONN_LOG = os.environ.get("CONN_LOG", os.path.join(HERE, "connections.log"))
ACTIONS_LOG = os.environ.get("ACTIONS_LOG", os.path.join(HERE, "actions.log"))


def write_log(path, obj):
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")


def log_connection(ip, port, name, kind):
    rec = {"ts": datetime.now().isoformat(timespec="seconds"),
           "ip": ip, "port": port, "honeypot": name, "kind": kind}
    write_log(CONN_LOG, rec)
    print(f"[sensor] {ip}:{port} connected to {name} ({kind})", flush=True)


def log_action(name, event, detail):
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "honeypot": name, "event": event}
    rec.update(detail)
    write_log(ACTIONS_LOG, rec)


class FleetStore(ModbusSlaveContext):
    """A Modbus store that logs every read/write, tagged with the honeypot name."""

    def __init__(self, name, **kw):
        super().__init__(**kw)
        self.hp_name = name

    def getValues(self, fc, address, count=1):
        log_action(self.hp_name, "read", {"address": address, "count": count})
        return super().getValues(fc, address, count)

    def setValues(self, fc, address, values):
        log_action(self.hp_name, "write", {"address": address, "values": list(values)})
        return super().setValues(fc, address, values)

    def feed(self, values):                       # our simulator updates quietly
        super().setValues(3, 0, values)


def simulate(store, device):
    """Update this device's registers every second so the values look alive."""
    while True:
        t = time.time()
        regs = []
        for (label, base, swing, period) in device["signals"]:
            v = base + swing * math.sin(2 * math.pi * t / period) + random.uniform(-0.2, 0.2)
            regs.append(max(0, int(v * 10)))       # x10, like the rest of the project
        store.feed(regs)
        time.sleep(1)


def run_backend(device):
    """Run ONE device's Modbus backend in its OWN process.

    Each device runs in a separate process on purpose: pymodbus keeps the device
    identity in class-level state, so devices sharing a process would all report
    the same identity. Separate processes (like separate real hardware) give each
    honeypot its own vendor / product / model, so they don't look like clones.
    """
    store = FleetStore(device["name"], hr=ModbusSequentialDataBlock(0, [0] * 100))
    context = ModbusServerContext(slaves=store, single=True)

    info = device["id"]
    ident = ModbusDeviceIdentification()
    ident.VendorName = info["vendor"]
    ident.ProductCode = info["product"]
    ident.ProductName = info["model"]
    ident.ModelName = info["model"]
    ident.MajorMinorRevision = info["version"]

    threading.Thread(target=simulate, args=(store, device), daemon=True).start()
    StartTcpServer(context=context, identity=ident, address=("127.0.0.1", device["internal"]))


def make_sensor(name, kind, internal_port):
    """Return a handler that logs the attacker's IP then relays to the backend."""
    async def handler(reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        log_connection(peer[0], peer[1], name, kind)
        try:
            backend_reader, backend_writer = await asyncio.open_connection("127.0.0.1", internal_port)
        except OSError:
            writer.close()
            return

        sent = {"n": 0}    # how many bytes the attacker actually sent

        async def pipe(src, dst, count=False):
            try:
                while True:
                    data = await src.read(4096)
                    if not data:
                        break
                    if count:
                        sent["n"] += len(data)
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(pipe(reader, backend_writer, count=True), pipe(backend_reader, writer))

        # if they connected but never sent any protocol data, it was a liveness
        # check / port scan -- "is this server alive?" -- so log it as a probe
        if sent["n"] == 0:
            log_action(name, "probe", {"ip": peer[0]})
    return handler


async def run_sensors():
    """Run the public sensors: log every source IP and relay to the backends."""
    for d in DEVICES:
        await asyncio.start_server(make_sensor(d["name"], d["kind"], d["internal"]), "0.0.0.0", d["public"])
    ports = f"{DEVICES[0]['public']}-{DEVICES[-1]['public']}"
    print(f"Honeypot fleet up: {len(DEVICES)} devices on ports {ports}. Ctrl+C to stop.", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    # each device backend runs in its OWN process -> its own device identity
    for device in DEVICES:
        multiprocessing.Process(target=run_backend, args=(device,), daemon=True).start()
    time.sleep(2)   # let the backends bind before the sensors relay to them
    try:
        asyncio.run(run_sensors())
    except KeyboardInterrupt:
        pass
