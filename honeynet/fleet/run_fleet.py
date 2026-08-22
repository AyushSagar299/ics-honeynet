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
import sys
import json
import time
import random
import signal
import socket
import asyncio
import logging
import threading
import multiprocessing
from datetime import datetime

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification

from devices import DEVICES
import attack_physics
from attack_physics import NOISE_FLOOR, NOISE_FRAC

HERE = os.path.dirname(os.path.abspath(__file__))
CONN_LOG = os.environ.get("CONN_LOG", os.path.join(HERE, "connections.log"))
ACTIONS_LOG = os.environ.get("ACTIONS_LOG", os.path.join(HERE, "actions.log"))
BIND = os.environ.get("FLEET_BIND", "0.0.0.0")   # set FLEET_BIND=127.0.0.1 to keep it off the LAN

# one physics model per device, shared by all the sensor handlers in this process
MODELS = {d["name"]: attack_physics.Model(d) for d in DEVICES}

# slow per-sensor calibration drift, so each channel wanders off its own zero a
# little over time like a real instrument that needs recalibrating
DRIFT_FRAC = 0.003       # random-walk step per tick, as a fraction of the signal's swing
DRIFT_MAX = 0.5          # never let the drift wander more than this fraction of swing away


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


BOOLEAN_SIGNALS = ("pump", "burner", "pump_a", "pump_b")


def simulate(store, device):
    """Drive each register with a stochastic, physics-aware model instead of a
    clock-locked sine, so the values cannot be curve-fitted or predicted and
    booleans behave like real 0/1 actuators.

    Each analog signal follows a mean-reverting random walk (it drifts around its
    normal value with realistic, size-scaled noise). On top of the true process
    value i add two things a real instrument has and a clean maths curve does not:
    fast Gaussian MEASUREMENT NOISE (the adc/sensor jitter you get on every read)
    and a slow per-sensor CALIBRATION DRIFT (a bias that wanders as the sensor's
    zero shifts). Together they stop the readings looking synthetic -- the project's
    own honeypot_detector was flagging the too-clean channels as fake.

    Booleans flip on random dwell times, and the actuators nudge the main process
    value (cause and effect). The generator is seeded from os.urandom, so every
    device and every restart differs and nothing is a function of the wall clock --
    there is no sine to fit."""
    rng = random.Random(os.urandom(16))
    sigs = device["signals"]
    state = []
    for (label, base, swing, period) in sigs:
        if label in BOOLEAN_SIGNALS:
            state.append(rng.random() < 0.5)
        else:
            state.append(base + rng.uniform(-0.3, 0.3) * swing)
    dwell = [rng.randint(20, 200) for _ in sigs]   # ticks a boolean holds its state
    drift = [0.0 for _ in sigs]                     # slow calibration bias per sensor
    dt = 0.2                                        # fast, off-grid tick (no 1s pattern)

    while True:
        push = 0.0
        for i, (label, base, swing, period) in enumerate(sigs):
            if label in BOOLEAN_SIGNALS:
                if dwell[i] <= 0:
                    state[i] = not state[i]
                    dwell[i] = rng.randint(20, 200)
                dwell[i] -= 1
                push += 1.0 if state[i] else -1.0

        regs = []
        for i, (label, base, swing, period) in enumerate(sigs):
            if label in BOOLEAN_SIGNALS:
                regs.append(int(bool(state[i])))          # a real 0/1 actuator
                continue
            theta = dt / max(period * 0.15, 1.0)          # how strongly it returns to normal
            sigma = max(0.02, 0.06 * swing)               # process noise scaled to this signal's range
            drive = theta * 0.8 * swing * push if i == 0 else 0.0  # actuators nudge the main value
            state[i] += theta * (base - state[i]) + drive + rng.gauss(0, sigma)
            lo, hi = max(0.0, base - 1.6 * swing), base + 1.6 * swing
            state[i] = min(hi, max(lo, state[i]))

            # the sensor's own zero wanders slowly (bounded random walk)
            drift[i] += rng.gauss(0, DRIFT_FRAC * swing)
            drift[i] = min(DRIFT_MAX * swing, max(-DRIFT_MAX * swing, drift[i]))
            # and every read carries fresh measurement noise on top
            meas = rng.gauss(0, max(NOISE_FLOOR, NOISE_FRAC * swing))
            reported = state[i] + drift[i] + meas
            regs.append(max(0, int(reported * 10)))
        store.feed(regs)
        time.sleep(dt)


def run_backend(device):
    """Run ONE device's Modbus backend in its OWN process.

    Each device runs in a separate process on purpose: pymodbus keeps the device
    identity in class-level state, so devices sharing a process would all report
    the same identity. Separate processes (like separate real hardware) give each
    honeypot its own vendor / product / model, so they don't look like clones.
    """
    logging.getLogger("pymodbus").setLevel(logging.CRITICAL)   # keep its chatter out of the demo output
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


async def read_frame(reader):
    """Read one whole Modbus/TCP frame (the MBAP header plus its PDU). Returns
    (frame_bytes, unit_id, pdu) or None on EOF or on anything that isn't Modbus we
    understand -- the caller treats None as 'connection done'."""
    try:
        head = await reader.readexactly(6)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        return None
    proto = int.from_bytes(head[2:4], "big")
    length = int.from_bytes(head[4:6], "big")
    if proto != 0 or length < 2 or length > 260:
        return None                                   # not a modbus frame -> give up on this conn
    try:
        rest = await reader.readexactly(length)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        return None
    return head + rest, rest[0], rest[1:]             # unit id is the first byte after the header


def parse_writes(pdu):
    """Pull the (kind, address, value) writes out of a write PDU so the physics can
    react to them. Handles the four write function codes."""
    fc = pdu[0]
    out = []
    if fc == 0x06:                                    # write single holding register
        out.append(("reg", int.from_bytes(pdu[1:3], "big"), int.from_bytes(pdu[3:5], "big")))
    elif fc == 0x10:                                  # write multiple holding registers
        start = int.from_bytes(pdu[1:3], "big")
        cnt = int.from_bytes(pdu[3:5], "big")
        data = pdu[6:6 + 2 * cnt]
        for k in range(min(cnt, len(data) // 2)):
            out.append(("reg", start + k, int.from_bytes(data[2 * k:2 * k + 2], "big")))
    elif fc == 0x05:                                  # write single coil
        raw = int.from_bytes(pdu[3:5], "big")
        out.append(("coil", int.from_bytes(pdu[1:3], "big"), 1 if raw == 0xFF00 else 0))
    elif fc == 0x0F:                                  # write multiple coils
        start = int.from_bytes(pdu[1:3], "big")
        cnt = int.from_bytes(pdu[3:5], "big")
        data = pdu[6:]
        for k in range(cnt):
            byte = data[k >> 3] if (k >> 3) < len(data) else 0
            out.append(("coil", start + k, (byte >> (k & 7)) & 1))
    return out


def build_write_response(frame, unit, pdu):
    """The reply a real PLC sends back for a write. Single writes just echo the
    request; multi-writes echo function code + start + count."""
    fc = pdu[0]
    if fc in (0x05, 0x06):
        return frame
    body = bytes([unit, fc]) + pdu[1:5]
    return frame[0:2] + b"\x00\x00" + len(body).to_bytes(2, "big") + body


def build_read_response(frame, unit, fc, regs):
    """Repack a read reply after we have swapped in the attacker's forked values."""
    data = b"".join(int(r).to_bytes(2, "big") for r in regs)
    body = bytes([unit, fc, len(data)]) + data
    return frame[0:2] + b"\x00\x00" + len(body).to_bytes(2, "big") + body


def response_delay(base):
    """A PLC-ish response time: a few ms base plus jitter, with the occasional
    longer outlier. Real embedded hardware answers in variable milliseconds; our
    userspace socket answers in ~0.2 ms with almost no spread, which an attacker can
    spot by timing 100 reads, so we slow each reply down to look like hardware."""
    d = base + abs(random.gauss(0, base * 0.5))
    if random.random() < 0.05:
        d += random.uniform(0.02, 0.05)               # every so often a slow scan cycle
    return d


def make_sensor(name, kind, internal_port):
    """Return a handler that logs the attacker's IP, then acts as a Modbus-aware
    relay to the backend. Reads are forwarded and their replies can be rewritten
    with this attacker's isolated fallout; writes are logged, fed to the per-source
    physics fork, and answered here (NOT forwarded), so the shared backend the rest
    of the world reads is never touched by an attacker."""
    base_latency = random.uniform(0.004, 0.012)       # this box's characteristic latency
    model = MODELS.get(name)

    async def handler(reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        ip = peer[0]
        log_connection(ip, peer[1], name, kind)
        try:
            backend_reader, backend_writer = await asyncio.open_connection("127.0.0.1", internal_port)
        except OSError:
            writer.close()
            return

        fork = attack_physics.get_fork(name, ip) if model else None
        sent = 0                                       # bytes of real protocol the attacker sent

        try:
            while True:
                got = await read_frame(reader)
                if got is None:
                    break
                frame, unit, pdu = got
                sent += len(frame)
                fc = pdu[0] if pdu else 0

                if model and fc in (0x05, 0x06, 0x0F, 0x10):
                    # a WRITE. log it, run this source's isolated fallout, and answer
                    # it ourselves. we deliberately do not forward it to the backend,
                    # so nothing the attacker writes reaches the shared live process.
                    writes = parse_writes(pdu)
                    log_action(name, "write", {"address": writes[0][1] if writes else None,
                                               "values": [w[2] for w in writes], "ip": ip})
                    attack_physics.apply_write(model, fork, writes, time.time())
                    fresh = attack_physics.take_new_alarms(fork)
                    if fresh:
                        log_action(name, "attack_physics",
                                   {"ip": ip, "forced": fork.summary, "alarm": "; ".join(fresh)})
                    await asyncio.sleep(response_delay(base_latency))
                    writer.write(build_write_response(frame, unit, pdu))
                    await writer.drain()
                    continue

                # everything else (reads, device identity, ...) goes to the backend
                backend_writer.write(frame)
                await backend_writer.drain()
                resp = await read_frame(backend_reader)
                if resp is None:
                    break
                rframe, runit, rpdu = resp
                rfc = rpdu[0] if rpdu else 0

                if model and fc in (0x03, 0x04) and rfc in (0x03, 0x04):
                    # a good register read. remember the clean values (for seeding a
                    # future fork), then if this source has already attacked, swap in
                    # what their attack turned the process into
                    start = int.from_bytes(pdu[1:3], "big")
                    count = int.from_bytes(pdu[3:5], "big")
                    bc = rpdu[1]
                    regs = [int.from_bytes(rpdu[2 + 2 * k:4 + 2 * k], "big") for k in range(bc // 2)]
                    attack_physics.note_read(model, fork, start, regs)
                    if fork.active:
                        regs = attack_physics.rewrite_reads(model, fork, start, count, regs, time.time())
                        rframe = build_read_response(rframe, runit, rfc, regs)
                        # an actuator attack only trips its alarm as the process reacts
                        # over the next reads, so log any alarm that has newly fired
                        fresh = attack_physics.take_new_alarms(fork)
                        if fresh:
                            log_action(name, "attack_physics",
                                       {"ip": ip, "forced": fork.summary, "alarm": "; ".join(fresh)})

                await asyncio.sleep(response_delay(base_latency))
                writer.write(rframe)
                await writer.drain()
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                backend_writer.close()
            except Exception:
                pass
            try:
                writer.close()
            except Exception:
                pass

        # connected but never sent any protocol data -> a liveness check / port scan
        if sent == 0:
            log_action(name, "probe", {"ip": ip})
    return handler


async def run_sensors(live):
    """Run the public sensors: log every source IP and relay to the backends."""
    for d in DEVICES:
        await asyncio.start_server(make_sensor(d["name"], d["kind"], d["internal"]), BIND, d["public"])
    ports = f"{DEVICES[0]['public']}-{DEVICES[-1]['public']}"
    print(f"Honeypot fleet up: {live} devices on ports {ports}. Ctrl+C to stop.", flush=True)
    await asyncio.Event().wait()


def wait_for_backends(procs, timeout=10.0):
    """Wait until each backend is really listening instead of guessing a sleep, and
    give back the names of the ones that never came up."""
    deadline = time.time() + timeout
    dead = []
    for d, p in zip(DEVICES, procs):
        while True:
            try:
                socket.create_connection(("127.0.0.1", d["internal"]), 0.2).close()
                break
            except OSError:
                # a backend whose port is already taken stays running but never
                # listens, so watch the clock as well as the process
                if not p.is_alive() or time.time() > deadline:
                    dead.append(d["name"])
                    break
                time.sleep(0.1)
    return dead


if __name__ == "__main__":
    # each device backend runs in its OWN process -> its own device identity
    backends = []
    for device in DEVICES:
        p = multiprocessing.Process(target=run_backend, args=(device,), daemon=True)
        p.start()
        backends.append(p)

    # on mac/linux stop_demo.sh kills us with SIGTERM. without this the backends
    # get left behind still holding ports 6101-6108 and the next run can't bind
    signal.signal(signal.SIGTERM, lambda sig, frm: sys.exit(0))

    dead = wait_for_backends(backends)
    if dead:
        print("backends that did not start (is the port already in use?): " + ", ".join(dead), flush=True)
    try:
        asyncio.run(run_sensors(len(DEVICES) - len(dead)))
    except KeyboardInterrupt:
        pass
    finally:
        for p in backends:
            p.terminate()
