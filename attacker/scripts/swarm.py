"""
swarm.py -- hit the honeynet with a swarm of bots all at once.

this does two separate things and keeps them honestly apart:

PART A -- the REAL result. spin up a few hundred bots at the same time. each bot
connects to a random device in the fleet (127.0.0.1 : 5101-5108) and does one
real modbus action: read the holding registers, an unauthorised write, or just
connect-and-drop (a scan). these are real sockets the fleet really logs. after
the burst i reconnect to all 8 devices and read them again to prove the honeynet
is still up. the "survived N bots" line is THIS, and it is true.

PART B -- the MAP demo. the whole lab is localhost, which has no place on a world
map. so, exactly like demo_attackers.py already does, i also write a batch of
EXAMPLE attacker sessions from public IPs around the world into the fleet logs,
so the threat console looks like a global wave. these are DEMONSTRATION data, not
real captures. on a deployed isolated network they would be real attackers; in
this localhost lab they are examples to show the geolocation / map feature.

  python swarm.py [bots]          # default 300

the printed summary keeps the two apart: which numbers are real load, and which
are example data for the map. only ever talks to 127.0.0.1 (see TARGET below).
"""

import os
import sys
import json
import time
import random
import socket
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from pymodbus.client import ModbusTcpClient

# --- where things live ------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))            # attacker/scripts -> repo root
FLEET = os.path.join(ROOT, "honeynet", "fleet")
CONN_LOG = os.path.join(FLEET, "connections.log")
ACTIONS_LOG = os.path.join(FLEET, "actions.log")

sys.path.insert(0, FLEET)                                # reuse the fleet's own code
from devices import DEVICES                              # the 8 honeypots (names, kinds, ports)
from geo import locate                                   # the SAME offline geoip the dashboard uses

# --- SAFETY: localhost only -------------------------------------------------
# every real connection the swarm makes goes to loopback and nowhere else.
# pointing a few-hundred-bot flood at a real internet host would be an attack and
# illegal, so the target is hardcoded here -- there is deliberately no host
# argument, you cannot point this at anything but 127.0.0.1.
TARGET = "127.0.0.1"
PORTS = [d["public"] for d in DEVICES]                   # 5101 .. 5108
assert TARGET == "127.0.0.1", "swarm may only ever target loopback"


# ===========================================================================
# PART A -- real concurrent load
# ===========================================================================

def one_bot(_i):
    """one attacker. pick a random fleet device, connect, do one real action.
    returns (kind, ok). every connection here is a real socket to 127.0.0.1 and
    the fleet logs it as a real capture (source ip 127.0.0.1)."""
    port = random.choice(PORTS)
    roll = random.random()
    try:
        if roll < 0.2:
            # scan: connect and drop without sending anything. the sensor sees 0
            # bytes and logs it as a probe (a port/liveness check).
            s = socket.create_connection((TARGET, port), timeout=3)
            s.close()
            return ("scan", True)

        c = ModbusTcpClient(TARGET, port=port, timeout=3)
        if not c.connect():
            return ("read" if roll < 0.75 else "write", False)
        if roll < 0.75:
            r = c.read_holding_registers(0, count=6)         # learn what it's doing
            kind, ok = "read", not r.isError()
        else:
            # unauthorised write -- modbus asks for no password. harmless on the
            # decoy and can never reach the real plant (one-way mirror).
            r = c.write_register(random.randint(0, 5), random.randint(0, 9999))
            kind, ok = "write", not r.isError()
        c.close()
        return (kind, ok)
    except Exception:
        return ("read", False)


def run_swarm(n):
    """launch n bots at once and wait for them all. returns (results, seconds)."""
    print(f"[swarm] launching {n} bots at {TARGET} ports {PORTS[0]}-{PORTS[-1]} ...", flush=True)
    t0 = time.time()
    results = []
    # one worker per bot so they really do hit the fleet concurrently (the burst),
    # not in small batches. pymodbus is blocking, so threads are the simple choice.
    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(one_bot, i) for i in range(n)]
        for f in as_completed(futs):
            results.append(f.result())
    return results, time.time() - t0


def still_alive(port):
    """AFTER the burst: can a normal client still connect and read this device?
    this is the real resilience check and its answer is truthful."""
    try:
        c = ModbusTcpClient(TARGET, port=port, timeout=5)
        if not c.connect():
            return False
        r = c.read_holding_registers(0, count=2)
        c.close()
        return not r.isError()
    except Exception:
        return False


# ===========================================================================
# PART B -- dashboard demo data (labelled example / demonstration data)
# ===========================================================================

# recognisable public anchors from several regions (the ~12 from demo_attackers.py,
# expanded). the rest of the pool is generated below and every ip is checked
# against the offline geoip so nothing lands on the map as "Unknown".
KNOWN_IPS = [
    "8.8.8.8", "77.88.55.66", "202.108.22.5", "1.1.1.1", "200.160.2.3",
    "62.210.16.1", "185.220.101.1", "103.86.98.1", "41.204.16.1",
    "193.0.14.129", "45.153.160.2", "210.140.92.1",
    "9.9.9.9", "208.67.222.222", "84.200.69.80", "156.154.70.1",
    "196.216.2.1", "203.119.101.1", "168.126.63.1", "80.249.99.148",
]


def build_demo_pool(n):
    """make n distinct EXAMPLE public IPs the offline geoip can place on the map.
    these are not real captures -- they are demonstration data (same idea as
    demo_attackers.py) so the world map has something to show. each ip is verified
    to resolve to a real country, so the map fills with real places."""
    pool, seen = [], set()
    for ip in KNOWN_IPS:
        if ip not in seen and not locate(ip)["is_local"]:
            seen.add(ip)
            pool.append(ip)
    rng = random.Random()
    guard = 0
    while len(pool) < n and guard < n * 60:
        guard += 1
        a = rng.randint(1, 223)
        b, c, d = rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254)
        # skip loopback / private / link-local so these look like real internet hosts
        if a in (0, 10, 127):
            continue
        if a == 192 and b == 168:
            continue
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 169 and b == 254:
            continue
        ip = f"{a}.{b}.{c}.{d}"
        if ip in seen or locate(ip)["is_local"]:
            continue
        seen.add(ip)
        pool.append(ip)
    return pool[:n]


def seed_dashboard(n_ips):
    """write example worldwide attacker sessions into the fleet logs so the threat
    console looks like a global wave. this is DEMONSTRATION data, written in the
    same json shape the fleet uses. returns (ips, conn_rows, countries)."""
    ips = build_demo_pool(n_ips)
    now = datetime.now()
    conns, acts = [], []

    for ip in ips:
        # give each example attacker a severity profile. the dashboard grades an
        # ip by how many DISTINCT honeypots it hits: >=5 critical, >=2 elevated,
        # 1 = recon. spread them so the console shows a mix.
        roll = random.random()
        if roll < 0.15:
            targets = random.randint(5, 8)          # critical
        elif roll < 0.45:
            targets = random.randint(2, 4)          # elevated
        else:
            targets = 1                             # recon
        for dev in random.sample(DEVICES, targets):
            for _ in range(random.randint(1, 3)):   # a few sessions per target
                ts = (now - timedelta(seconds=random.randint(0, 1200))).isoformat(timespec="seconds")
                conns.append({"ts": ts, "ip": ip, "port": random.randint(1024, 65000),
                              "honeypot": dev["name"], "kind": dev["kind"]})
                # a matching action, same shape run_fleet.py writes
                a = random.random()
                if a < 0.6:
                    acts.append({"ts": ts, "honeypot": dev["name"], "event": "read",
                                 "address": 0, "count": 6})
                elif a < 0.85:
                    acts.append({"ts": ts, "honeypot": dev["name"], "event": "write",
                                 "address": random.randint(0, 5), "values": [random.randint(0, 9999)]})
                else:
                    acts.append({"ts": ts, "honeypot": dev["name"], "event": "probe", "ip": ip})

    conns.sort(key=lambda x: x["ts"])
    acts.sort(key=lambda x: x["ts"])
    with open(CONN_LOG, "a", encoding="utf-8") as f:
        for row in conns:
            f.write(json.dumps(row) + "\n")
    with open(ACTIONS_LOG, "a", encoding="utf-8") as f:
        for row in acts:
            f.write(json.dumps(row) + "\n")

    countries = sorted({locate(ip)["country"] for ip in ips})
    return ips, conns, countries


# ===========================================================================
# main -- run part A, then part B, then print the two blocks side by side
# ===========================================================================

if __name__ == "__main__":
    bots = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    bots = max(1, min(bots, 500))          # clamp so a typo can't spawn a runaway swarm

    # ---- PART A: real concurrent load ----
    results, elapsed = run_swarm(bots)
    ok = sum(1 for _, good in results if good)
    failed = len(results) - ok
    reads = sum(1 for k, _ in results if k == "read")
    writes = sum(1 for k, _ in results if k == "write")
    scans = sum(1 for k, _ in results if k == "scan")
    rate = len(results) / elapsed if elapsed else 0

    print("[swarm] burst done, checking the honeynet is still alive ...", flush=True)
    alive = {p: still_alive(p) for p in PORTS}
    up = sum(1 for v in alive.values() if v)
    dead = [p for p, v in alive.items() if not v]

    # ---- PART B: dashboard demo data ----
    ips, conns, countries = seed_dashboard(bots)

    # ---- summary: two clearly separated blocks ----
    print()
    print("=" * 70)
    print("REAL LOAD  (this actually happened, every connection to 127.0.0.1):")
    print(f"  {bots} bots, {len(results)} connections in {elapsed:.1f}s ({rate:.0f}/sec)")
    print(f"  mix: {reads} reads, {writes} writes, {scans} scans   ({ok} ok, {failed} failed)")
    if up == len(PORTS):
        print(f"  after the burst: all {up} of {len(PORTS)} devices still answer a normal read")
        print(f"  => the honeynet SURVIVED a {bots}-bot swarm.")
    else:
        print(f"  after the burst: {up}/{len(PORTS)} still answering; NOT responding: ports {dead}")
        print(f"  => {len(dead)} device(s) stopped responding under the load.")
    print("-" * 70)
    print("DASHBOARD VIEW  (EXAMPLE data for the map, NOT real captures):")
    print(f"  seeded {len(ips)} example attacker IPs across {len(countries)} countries")
    print(f"  ({len(conns)} example sessions written to the fleet logs, mixed severities)")
    print("  on a deployed isolated network these would be real attackers; in this")
    print("  localhost lab they are demonstration data for the map. see the console:")
    print("  http://localhost:8100")
    print("=" * 70)
