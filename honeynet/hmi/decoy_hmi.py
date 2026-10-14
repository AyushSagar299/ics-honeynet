"""
decoy_hmi.py -- a fake HMI login page (a honeypot).

It looks like the login screen of a plant operator panel. There is no real
account behind it -- it always rejects the login. But it LOGS every attempt
(username, password, source IP), so a credential brute-force attack against it
is fully recorded. That log is evidence for the project.

It also plants HONEYTOKENS. There is a fake "backups" area at /files with the
kind of files an attacker hunts for on an HMI: a plc password list, a map of
the OT network, and a TIA Portal project archive. All three are generated
dummies (fictional plant, private lab addresses, default style passwords),
there is no real secret in any of them -- the bait is that an attacker does
not know that. When somebody opens the listing or downloads a file, a high
severity event goes to the fleet actions.log (same JSON line shape the fleet
writes) with the matching MITRE ATT&CK for ICS technique, so the threat
dashboard shows the theft next to the modbus activity. Breadcrumbs pointing
at /files: a small maintenance link on the login page, a TODO comment in the
page source, and a Disallow line in robots.txt.

honest limit: this detects the token being TAKEN from the decoy, locally.
Detecting the token being USED later somewhere else on the internet (a real
canary token callback like canarytokens.org) needs a public callback service
and an endpoint reachable from outside, and this lab is isolated on
localhost. So I only claim local access/exfil detection, not internet wide
reuse detection.

The HMI never opens a connection to anything. It only serves the bait files
and appends log lines, so it cannot touch the plant, the bridge or the shadow.
"""

import os
import json
import datetime

from flask import Flask, request, send_from_directory, abort

app = Flask(__name__)
HERE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get("HMI_LOG", "hmi_attempts.log")
PORT = int(os.environ.get("HMI_PORT", "8090"))

# the fleet logs live in honeynet/fleet. i append to the same files so the
# existing dashboard picks these events up without any change on its side.
ACTIONS_LOG = os.environ.get("ACTIONS_LOG", os.path.join(HERE, "..", "fleet", "actions.log"))
CONN_LOG = os.environ.get("CONN_LOG", os.path.join(HERE, "..", "fleet", "connections.log"))
HP_NAME = "decoy-hmi"

BAIT_DIR = os.path.join(HERE, "bait")

# the honeytokens. the dict doubles as a whitelist for the download route, so
# only these exact names can ever be served (no ../ tricks). each one carries
# the MITRE ATT&CK for ICS technique its theft maps to.
BAIT = {
    "plc_passwords.txt": {
        "desc": "device passwords (ops copy)",
        "mitre": "T0882", "mitre_name": "Theft of Operational Information",
    },
    "ot_network_map.txt": {
        "desc": "OT network overview",
        "mitre": "T0882", "mitre_name": "Theft of Operational Information",
    },
    "WTP1_pumps_v13.zap17": {
        "desc": "TIA Portal project archive (PLC program backup)",
        "mitre": "T0882", "mitre_name": "Theft of Operational Information",
    },
}

# what goes inside the bait files. everything here is made up: the plant is
# fictional, the addresses are rfc1918 lab ranges that route nowhere, and the
# passwords are the textbook defaults nobody real should be using.
BAIT_CONTENT = {
    "plc_passwords.txt": """waterworks WTP-1 device passwords -- ops copy, do not share
(kept here because the vault is always down when we need it)

PLC-01   S7-1200    192.168.10.11   admin / admin1234
PLC-02   S7-1200    192.168.10.12   admin / admin1234
HMI-01   KTP700     192.168.10.20   operator / operator
HIST-01  historian  192.168.10.30   sa / Password1
EWS-01   tia v17    192.168.10.40   plant / plant2019
router              192.168.10.1    admin / changeme

most of these are still the defaults from commissioning.
""",
    "ot_network_map.txt": """waterworks WTP-1 -- OT network overview (plain text export of the visio)

internet
  |
firewall / router  192.168.10.1
  |
  +-- IT vlan 10 : office pcs, printer, mail
  |
  +-- OT vlan 20 :
        192.168.10.11  PLC-01   siemens s7-1200   intake pumps
        192.168.10.12  PLC-02   siemens s7-1200   chemical dosing
        192.168.10.20  HMI-01   ktp700 panel      operator screen
        192.168.10.30  HIST-01  windows + sql     process historian
        192.168.10.40  EWS-01   tia portal v17    engineering workstation

remote access: vnc on EWS-01, password is on the whiteboard.
""",
    "WTP1_pumps_v13.zap17": """PK
[placeholder for a TIA Portal V17 project archive]
project : WTP1_pumps_v13
station : S7-1200, CPU 1214C DC/DC/DC
author  : maintenance

note: this is a generated dummy file for the decoy. a real .zap17 is a zip
archive made by TIA Portal, this one contains no program logic at all.
""",
}


def write_bait():
    # generate the bait files next to this script if they are not there yet
    os.makedirs(BAIT_DIR, exist_ok=True)
    for name, text in BAIT_CONTENT.items():
        path = os.path.join(BAIT_DIR, name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def append_line(path, obj):
    # never let a logging problem take the decoy down
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + "\n")
    except OSError as e:
        print("could not write", path, e, flush=True)


def log_token_event(event, asset, mitre, mitre_name, severity):
    """One line to actions.log (same shape the fleet writes) and one to
    connections.log, so the dashboard's attacker table and live feed show the
    hmi hit like any other honeypot connection."""
    ip = request.remote_addr or "?"
    rec = {"ts": now(), "honeypot": HP_NAME, "event": event,
           "asset": asset, "severity": severity,
           "mitre": mitre, "mitre_name": mitre_name, "ip": ip}
    append_line(ACTIONS_LOG, rec)
    try:
        sport = int(request.environ.get("REMOTE_PORT") or 0)
    except (TypeError, ValueError):
        sport = 0
    append_line(CONN_LOG, {"ts": now(), "ip": ip, "port": sport,
                           "honeypot": HP_NAME, "kind": "hmi honeytoken"})
    print(f"[{severity.upper()}] {event}: {asset} taken by {ip} ({mitre} {mitre_name})", flush=True)


PAGE = """<html><body style="font-family:sans-serif">
<h2>WaterWorks SCADA &mdash; Operator Login</h2>
<form method="post" action="/login">
  User: <input name="username"><br><br>
  Pass: <input name="password" type="password"><br><br>
  <input type="submit" value="Login">
</form>
<p style="font-size:12px;color:#888">maintenance: <a href="/files">backup files</a></p>
<!-- TODO move /files behind the login before go-live -->
</body></html>"""


@app.route("/")
def index():
    return PAGE


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        entry = {
            "ts": now(),
            "ip": request.remote_addr,
            "username": request.form.get("username", ""),
            "password": request.form.get("password", ""),
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print("login attempt:", entry, flush=True)
        # always fail -- it is a honeypot, there is nothing to log into
        return PAGE + "<p>Invalid credentials</p>", 401
    return PAGE


@app.route("/robots.txt")
def robots():
    # a classic breadcrumb -- attackers read robots.txt first to see what a
    # site is trying to hide, so "hide" the backups in it
    return "User-agent: *\nDisallow: /files/\n", 200, {"Content-Type": "text/plain"}


@app.route("/files")
@app.route("/files/")
def files_index():
    # just finding the repository is already worth an alert (they are browsing
    # for operational data), but the download itself is the high one
    log_token_event("honeytoken_browse", "file listing", "T0811",
                    "Data from Information Repositories", severity="medium")
    rows = "".join(
        f'<li><a href="/files/{name}">{name}</a> &mdash; {info["desc"]}</li>'
        for name, info in BAIT.items())
    return (f"""<html><body style="font-family:sans-serif">
<h3>WaterWorks SCADA &mdash; maintenance backups</h3>
<ul>{rows}</ul>
<p style="font-size:12px;color:#888"><a href="/">back to login</a></p>
</body></html>""")


@app.route("/files/<name>")
def files_get(name):
    info = BAIT.get(name)     # whitelist lookup, unknown names 404
    if info is None:
        abort(404)
    log_token_event("honeytoken_access", name, info["mitre"],
                    info["mitre_name"], severity="high")
    return send_from_directory(BAIT_DIR, name, as_attachment=True)


write_bait()

if __name__ == "__main__":
    print(f"Decoy HMI login honeypot on port {PORT}. Every attempt is logged.", flush=True)
    print(f"Honeytokens planted in {BAIT_DIR} (all dummy content).", flush=True)
    app.run(host=os.environ.get("FLEET_BIND", "0.0.0.0"), port=PORT)
