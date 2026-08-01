"""
dashboard.py -- the Honeynet Threat Intelligence dashboard.

It reads the fleet's two logs and turns them into attacker intelligence:
  connections.log -> who connected (source IP), and to which honeypot
  actions.log     -> what they did on each honeypot (reads / writes)

Shows: the fleet of honeypots, a table of attacker IPs (with the honeypots each
one hit), and a live connection feed. Open http://localhost:8100 .
"""

import os
import json
import time

from flask import Flask, jsonify, send_from_directory, Response

from devices import DEVICES
from geo import locate

HERE = os.path.dirname(os.path.abspath(__file__))
CONN_LOG = os.environ.get("CONN_LOG", os.path.join(HERE, "connections.log"))
ACTIONS_LOG = os.environ.get("ACTIONS_LOG", os.path.join(HERE, "actions.log"))

app = Flask(__name__)


def load(path):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    return rows


def build():
    conns = load(CONN_LOG)
    acts = load(ACTIONS_LOG)

    # group connections by attacker IP
    by_ip = {}
    for c in conns:
        ip = c.get("ip", "?")
        d = by_ip.setdefault(ip, {"ip": ip, "connections": 0, "honeypots": set(),
                                  "first": c["ts"], "last": c["ts"]})
        d["connections"] += 1
        d["honeypots"].add(c.get("honeypot"))
        d["first"] = min(d["first"], c["ts"])
        d["last"] = max(d["last"], c["ts"])
    attackers = [{"ip": d["ip"], "connections": d["connections"],
                  "targets": len(d["honeypots"]), "honeypots": sorted(d["honeypots"]),
                  "first": d["first"], "last": d["last"]} for d in by_ip.values()]
    attackers.sort(key=lambda x: -x["connections"])

    # enrich each attacker IP with a location (offline lookup)
    for a in attackers:
        a.update(locate(a["ip"]))

    # tally connections by country, for the "top locations" panel
    loc = {}
    for a in attackers:
        key = (a["country"], a["flag"])
        loc[key] = loc.get(key, 0) + a["connections"]
    top_locations = [{"country": k[0], "flag": k[1], "count": v}
                     for k, v in sorted(loc.items(), key=lambda x: -x[1])]
    countries = len({a["country"] for a in attackers if not a["is_local"]})

    # per-honeypot activity
    stats = {d["name"]: {"name": d["name"], "kind": d["kind"], "conns": 0,
                         "reads": 0, "writes": 0, "probes": 0, "last": None} for d in DEVICES}
    # a honeypot that is not in devices.py -- the OPC UA decoy is its own program,
    # not part of the modbus fleet -- would be dropped by the loops below, so add
    # it here from what its own connection lines say it is
    for c in conns:
        name = c.get("honeypot")
        if name and name not in stats:
            stats[name] = {"name": name, "kind": c.get("kind", "honeypot"), "conns": 0,
                           "reads": 0, "writes": 0, "probes": 0, "last": None}
    for a in acts:
        s = stats.get(a.get("honeypot"))
        if s:
            if a.get("event") == "read":
                s["reads"] += 1
            elif a.get("event") == "write":
                s["writes"] += 1
            elif a.get("event") == "probe":
                s["probes"] += 1
            s["last"] = a["ts"]
    for c in conns:
        if c.get("honeypot") in stats:
            stats[c["honeypot"]]["conns"] += 1
    fleet = list(stats.values())

    feed = sorted(conns, key=lambda x: x["ts"], reverse=True)[:20]
    kpis = {"honeypots": len(fleet),          # the fleet plus any decoy outside devices.py
            "active": sum(1 for s in fleet if s["conns"] > 0),
            "attackers": len(attackers),
            "countries": countries,
            "connections": len(conns),
            "probes": sum(s["probes"] for s in fleet),
            "writes": sum(s["writes"] for s in fleet)}
    return {"kpis": kpis, "attackers": attackers, "fleet": fleet,
            "feed": feed, "top_locations": top_locations}


@app.route("/")
def index():
    return send_from_directory(HERE, "dashboard.html")


@app.route("/api/threat")
def threat():
    return jsonify(build())


@app.route("/api/stream")
def stream():
    """Server-Sent Events: hold the connection open and PUSH the new state to
    the browser whenever something changes (a new attacker connection or action).
    No polling from the browser -- this is real-time broadcast."""
    def events():
        last = None
        while True:
            payload = json.dumps(build())
            if payload != last:                 # only push when something changed
                last = payload
                yield f"data: {payload}\n\n"
            else:
                yield ": keep-alive\n\n"          # comment line keeps the connection open
            time.sleep(1)
    return Response(events(), mimetype="text/event-stream")


if __name__ == "__main__":
    print("Honeynet Threat Intelligence on http://localhost:8100", flush=True)
    # threaded=True so a streaming connection doesn't block the other routes
    app.run(host="0.0.0.0", port=int(os.environ.get("DASH_PORT", "8100")), threaded=True)
