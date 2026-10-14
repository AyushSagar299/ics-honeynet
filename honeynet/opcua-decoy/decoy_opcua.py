"""
decoy_opcua.py -- an OPC UA decoy for the honeynet.

Why I added it: the whole honeynet only spoke Modbus, and that is a tell. A real
site has a modern OPC UA capable PLC as well, so a plant that answers on exactly
one protocol looks thin. This decoy adds the second protocol, and it serves the
SAME kind of live moving water-plant values as the Modbus fleet, so both
protocols tell one consistent story.

Like the fleet it is two pieces:
  * a BACKEND -- the asyncua OPC UA server, bound to 127.0.0.1 only, that
    simulates the values and logs every read/write of them;
  * a SENSOR -- a small relay on the public port (4840) that logs the attacker's
    real source IP the moment they connect, then forwards to the backend. Same
    trick as run_fleet.py, and the fleet README already said this is how a future
    OPC UA decoy should be wired.

It writes the SAME two log files, in the same JSON shape, as the Modbus fleet:
  connections.log -- one line per attacker connection
  actions.log     -- one line per read / write / probe
so the Threat Console on http://localhost:8100 shows OPC UA attackers right next
to the Modbus ones.

Safety: this never opens a connection towards the real plant. Every value it
serves is made up here, in this process, and anything an attacker writes stays
here too.

Known difference from the Modbus fleet: the fleet gives every source IP its own
private fork, so a write is only ever seen by the attacker who made it. Here
there is one shared PLANT, so a write is seen by every OPC UA client until the
value drifts back. Still contained (nothing leaves this process), but not
isolated per attacker. Doing it properly means a per-session view of reads,
writes and subscriptions inside asyncua, which I left as future work.
"""

import os
import sys
import json
import random
import signal
import asyncio
import logging
from datetime import datetime

from asyncua import Server, ua
from asyncua.server.internal_server import InternalServer
from asyncua.server.internal_session import InternalSession
from asyncua.crypto.permission_rules import User, UserRole

HERE = os.path.dirname(os.path.abspath(__file__))
FLEET_DIR = os.path.join(os.path.dirname(HERE), "fleet")     # the logs live with the fleet
CONN_LOG = os.environ.get("CONN_LOG", os.path.join(FLEET_DIR, "connections.log"))
ACTIONS_LOG = os.environ.get("ACTIONS_LOG", os.path.join(FLEET_DIR, "actions.log"))

PORT = int(os.environ.get("OPCUA_PORT", "4840"))             # what the attacker connects to
BACKEND_PORT = int(os.environ.get("OPCUA_BACKEND_PORT", "4841"))   # the real server, localhost only
BIND = os.environ.get("FLEET_BIND", "0.0.0.0")               # set FLEET_BIND=127.0.0.1 to keep it off the LAN

NAME = "OPCUA-PLC-09"                     # 01-08 are the Modbus fleet, this one is next
KIND = "Water treatment PLC (OPC UA)"

# a believable identity, same idea as the "id" entries in fleet/devices.py: a real
# vendor / product / model / firmware. An S7-1500 is the obvious pick because that
# is the classic PLC that really does run an OPC UA server.
IDENTITY = {"vendor": "Siemens AG", "product": "6ES7516-3AN02-0AB0",
            "model": "SIMATIC S7-1500 CPU 1516-3 PN/DP", "version": "V2.9.4"}

# same (label, base, swing, period) shape as fleet/devices.py, and the same values
# as WATER-TANK-01, because this is meant to be another PLC in the same water plant
SIGNALS = [("level_%", 60, 25, 90), ("temp_C", 23, 4, 140),
           ("pressure_bar", 6, 2, 90), ("pump", 1, 1, 60)]
BOOLEAN_SIGNALS = ("pump",)
DT = 1.0                                  # we push new values once a second


def write_log(path, obj):
    with open(path, "a", encoding="utf-8") as f:
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


class Plant:
    """The values the decoy serves.

    This is the same model run_fleet.simulate() uses, just kept in a small class
    instead of a thread: every analog signal is a mean-reverting random walk
    around its normal value, the pump flips on random dwell times and nudges the
    level up or down (cause and effect), and the generator is seeded from
    os.urandom. So there is no clock-locked sine anyone could curve-fit, and the
    OPC UA values drift exactly like the Modbus ones.
    """

    def __init__(self):
        self.rng = random.Random(os.urandom(16))
        self.state = []
        for (label, base, swing, period) in SIGNALS:
            if label in BOOLEAN_SIGNALS:
                self.state.append(self.rng.random() < 0.5)
            else:
                self.state.append(base + self.rng.uniform(-0.3, 0.3) * swing)
        # 5-50 ticks at 1s = the same 5-50 seconds the fleet uses at its faster tick
        self.dwell = [self.rng.randint(5, 50) for _ in SIGNALS]

    def step(self):
        push = 0.0
        for i, (label, base, swing, period) in enumerate(SIGNALS):
            if label in BOOLEAN_SIGNALS:
                if self.dwell[i] <= 0:
                    self.state[i] = not self.state[i]
                    self.dwell[i] = self.rng.randint(5, 50)
                self.dwell[i] -= 1
                push += 1.0 if self.state[i] else -1.0

        for i, (label, base, swing, period) in enumerate(SIGNALS):
            if label in BOOLEAN_SIGNALS:
                continue
            theta = DT / max(period * 0.15, 1.0)       # how strongly it returns to normal
            sigma = max(0.02, 0.06 * swing)            # noise scaled to this signal's range
            drive = theta * 0.8 * swing * push if i == 0 else 0.0   # the pump moves the level
            self.state[i] += theta * (base - self.state[i]) + drive + self.rng.gauss(0, sigma)
            lo, hi = max(0.0, base - 1.6 * swing), base + 1.6 * swing
            self.state[i] = min(hi, max(lo, self.state[i]))

    def values(self):
        out = {}
        for i, (label, base, swing, period) in enumerate(SIGNALS):
            if label in BOOLEAN_SIGNALS:
                out[label] = bool(self.state[i])
            else:
                out[label] = round(float(self.state[i]), 2)
        return out

    def take_write(self, label, value):
        """An attacker wrote a value, so take it into the model. The next ticks
        then drift away from THAT value instead of snapping back a second later,
        which is what a real process would look like (and the analog range limit
        pulls a silly value like 9999 back in, like a real analog input would)."""
        for i, (lab, base, swing, period) in enumerate(SIGNALS):
            if lab != label:
                continue
            if lab in BOOLEAN_SIGNALS:
                self.state[i] = bool(value)
                self.dwell[i] = self.rng.randint(5, 50)
            else:
                try:
                    self.state[i] = float(value)
                except (TypeError, ValueError):
                    pass


PLANT = Plant()
VARS = {}        # nodeid -> signal label, filled in when the nodes are built
PEERS = {}       # sensor's local port -> the attacker's real ip (see the sensor below)


def peer_ip(session_name):
    """asyncua names an external session after the peer address of the socket it
    saw. The attacker comes in through our sensor, so that socket is the sensor's
    own one -- look the real IP up by the port the sensor used."""
    if isinstance(session_name, (tuple, list)) and len(session_name) >= 2:
        return PEERS.get(session_name[1], str(session_name[0]))
    return "?"


class SpyingSession(InternalSession):
    """The hook that lets us log reads.

    asyncua gives you no "somebody read my variable" callback, but every request
    a client makes goes through its session object, so I subclass that and write
    the reads and writes into actions.log on the way past. self.external is only
    True for a real client, so our own simulator updates are not logged, and I
    only log the plant variables -- the housekeeping reads the OPC UA stack does
    when a client connects are not attacker activity.
    """

    async def read(self, params):
        if self.external:
            for item in params.NodesToRead:
                label = VARS.get(item.NodeId)
                if label and item.AttributeId == ua.AttributeIds.Value:
                    log_action(NAME, "read", {"node": label, "ip": peer_ip(self.name)})
        return await super().read(params)

    async def write(self, params):
        results = await super().write(params)
        if self.external:
            for item, status in zip(params.NodesToWrite, results):
                label = VARS.get(item.NodeId)
                if not label or item.AttributeId != ua.AttributeIds.Value:
                    continue
                value = item.Value.Value.Value if item.Value and item.Value.Value else None
                ok = not status.is_bad()
                log_action(NAME, "write", {"node": label, "value": value,
                                           "accepted": ok, "ip": peer_ip(self.name)})
                if ok:
                    PLANT.take_write(label, value)
        return results


class SpyingServer(InternalServer):
    """Same server asyncua normally builds, but it hands out our spying sessions."""

    def create_session(self, name, user=User(role=UserRole.Anonymous), external=False):
        return SpyingSession(self, self.aspace, self.subscription_service, name,
                             user=user, external=external)


async def build_server():
    """Build the OPC UA server: identity first, then the plant variables."""
    server = Server(iserver=SpyingServer())
    await server.init()

    # what we tell the world we are. init() writes its own default build info, so
    # this has to come after it.
    server.set_server_name("SIMATIC S7-1500 OPC UA Server")
    await server.set_application_uri("urn:SIMATIC.S7-1500.OPC-UA.Application:PLC_09")
    await server.set_build_info("urn:siemens.com:SIMATIC.S7-1500", IDENTITY["vendor"],
                                IDENTITY["model"], IDENTITY["version"], IDENTITY["product"],
                                datetime(2023, 3, 14))

    # the URL we advertise is the public port, but we really listen on localhost:
    # the sensor owns the public port and relays to us
    server.set_endpoint(f"opc.tcp://{BIND}:{PORT}/plc/")
    server.socket_address = ("127.0.0.1", BACKEND_PORT)

    idx = await server.register_namespace("http://siemens.com/simatic-s7-opcua")
    plc = await server.nodes.objects.add_object(idx, "PLC_09")

    # a small device info folder, the sort of thing a real PLC exposes when you
    # browse it, so "who are you?" gets a believable answer here too
    info = await plc.add_object(idx, "DeviceInfo")
    await info.add_variable(idx, "Manufacturer", IDENTITY["vendor"])
    await info.add_variable(idx, "Model", IDENTITY["model"])
    await info.add_variable(idx, "OrderNumber", IDENTITY["product"])
    await info.add_variable(idx, "FirmwareVersion", IDENTITY["version"])
    await info.add_variable(idx, "SerialNumber", "S C-K1V284652019")

    process = await plc.add_object(idx, "WaterTreatment")
    nodes = {}
    for label, value in PLANT.values().items():
        var = await process.add_variable(idx, label, value)
        await var.set_writable()          # no authentication, on purpose: it is the lure
        nodes[label] = var
        VARS[var.nodeid] = label
    return server, nodes


async def feed(nodes):
    """Push new values into the server once a second, so anyone reading (or
    subscribing) sees a plant that is alive."""
    while True:
        PLANT.step()
        values = PLANT.values()
        for label, node in nodes.items():
            await node.write_value(values[label])
        await asyncio.sleep(DT)


async def sensor_client(reader, writer):
    """One attacker connection: log the source IP, then relay it to the backend."""
    peer = writer.get_extra_info("peername") or ("?", 0)
    log_connection(peer[0], peer[1], NAME, KIND)
    try:
        backend_reader, backend_writer = await asyncio.open_connection("127.0.0.1", BACKEND_PORT)
    except OSError:
        writer.close()
        return

    # tell the server which attacker this connection belongs to, so the reads and
    # writes it logs carry the real IP and not our own relay address
    local = backend_writer.get_extra_info("sockname") or ("?", 0)
    PEERS[local[1]] = peer[0]
    sent = {"n": 0}          # how many bytes the attacker actually sent

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
    PEERS.pop(local[1], None)

    # connected but never sent anything = a port scan / liveness check, same as the fleet
    if sent["n"] == 0:
        log_action(NAME, "probe", {"ip": peer[0]})


def stop_on_signals(stop):
    """Ctrl+C and SIGTERM (stop_demo.sh) both mean: shut down and free the port."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, AttributeError):
            # windows has no add_signal_handler, fall back to the plain one
            signal.signal(sig, lambda s, f: stop.set())


async def main():
    logging.getLogger("asyncua").setLevel(logging.CRITICAL)   # keep its chatter out of the demo output
    server, nodes = await build_server()
    await server.start()
    feeder = asyncio.create_task(feed(nodes))
    sensor = await asyncio.start_server(sensor_client, BIND, PORT)

    stop = asyncio.Event()
    stop_on_signals(stop)
    print(f"OPC UA decoy up: {NAME} on port {PORT}, pretending to be a "
          f"{IDENTITY['model']}. Ctrl+C to stop.", flush=True)
    try:
        await stop.wait()
    finally:
        feeder.cancel()
        sensor.close()
        await sensor.wait_closed()
        await server.stop()
        print("OPC UA decoy stopped.", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
