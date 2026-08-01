# The honeypot fleet + threat intelligence

This turns the single decoy into a **honeynet**: a whole plant of fake devices,
each capturing the attacker's real source IP.

## What's here
- `devices.py` — the 8 fake devices (water tank, boiler, pump station, chlorine
  doser, power meter, HVAC, conveyor, generator). Add more by editing this list.
- `run_fleet.py` — starts every device. For each one it runs:
  - a **backend** Modbus decoy (self-simulating realistic values, bound to
    `127.0.0.1` only) that logs every read/write, and
  - a **sensor** on the public port that logs the attacker's **source IP** the
    moment they connect, then forwards to the backend.
- `dashboard.py` + `dashboard.html` — the **threat-intelligence dashboard**
  (attacker IPs **and country**, which honeypots they hit, tamper writes, live feed).
  Updates are **pushed** to the browser in real time via Server-Sent Events
  (`/api/stream`) — the browser does not poll; the server broadcasts new state the
  moment an attacker connects.
- `geo.py` — offline IP -> country lookup (uses `geoip2fast`; no API key, nothing
  leaves the machine). Localhost/private ranges are labelled "Local".
- `demo_attackers.py` — append example global attacker IPs so the map/country
  view has something to show (lab traffic is all localhost). Clearly demo data.
- `replay_csv.py` — drive a honeypot from a **real dataset** (see below).

## Why the sensor (source-IP capture)
pymodbus does not expose the client IP for TCP connections (its `request_tracer`
hook only gets the address for UDP). So a small async relay sits in front of each
honeypot: it records `(ip, port, honeypot)` on connect and relays the traffic.
Bonus: it's protocol-agnostic, so the same sensor works for any future decoy.

## Run it
```bash
../../.venv/bin/python run_fleet.py       # the 8 honeypots (ports 5101-5108)
../../.venv/bin/python dashboard.py        # http://localhost:8100
```
It writes two logs (git-ignored):
- `connections.log` — one line per attacker connection (the IPs)
- `actions.log` — one line per read/write (what they did, on which honeypot)

## Using a real dataset
```bash
../../.venv/bin/python replay_csv.py sample_dataset.csv 5200 tank_level water_temp pump inflow_lps
```
This serves the CSV's rows over Modbus, one per second. Swap in a real ICS
dataset to make a honeypot show values that actually came from a real plant:
- **HAI** — publicly downloadable, labelled attacks (easiest).
- **SWaT / WADI** — iTrust water-treatment testbed (request form; the gold standard).
- **Morris / Mississippi State SCADA** — directly downloadable, Modbus-specific.

A dataset helps most in the **analysis chapter** (a labelled set lets you test your
anomaly detection against real attacks).

## Status / next
Every honeypot in *this* folder speaks **Modbus**. The **OPC UA** decoy is now
done as well (`../opcua-decoy/decoy_opcua.py`, port 4840): it runs its own
`asyncua` server behind the same kind of sensor and appends to these same two
logs, so the dashboard shows it (`OPCUA-PLC-09`) next to the Modbus ones. The
next step for a truly *mixed* fleet is an **S7** decoy (`python-snap7`, needs
`brew install snap7`) behind its own sensor.
