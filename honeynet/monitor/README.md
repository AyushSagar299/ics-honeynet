# Honeynet Operations Console

A single live dashboard that shows the plant telemetry **and** the captured
attacks in one screen. It is the lightweight stand-in for Kibana — instead of
the heavy ELK stack (too big for a 4 GB Mac), it reads the real PLC and the
static decoy over Modbus, follows the **live decoy on MQTT** (so its own polling
never pollutes the honeypot log), and tails the honeypot JSON logs.

![what it looks like: dark SOC dashboard with KPI tiles, a twin-fidelity chart
(real PLC + live decoy tracking, static decoy flat), decoy comparison cards, and
a live attack feed]

## What it shows
- **KPI tiles** — level, temperature, pressure (vs expected), plant status
  (nominal / anomaly), attacker event count, brute-force count.
- **Twin fidelity chart** — real PLC vs live decoy vs static decoy, live.
- **Decoys vs reality** — live decoy `MOVING`, static decoy `FROZEN`.
- **Live attack feed** — every read / write / login the honeynet captured.

## Run it
It needs the lab running (real PLC, bridge, twin, decoys, HMI) so it has
something to show — see the top-level README. Then:
```bash
# point it at the same logs the decoy + HMI write to
DECOY_LOG=$PWD/analysis/decoy.log HMI_LOG=$PWD/analysis/hmi.log \
  ../.venv/bin/python console.py
# open http://localhost:8099
```
Ports it reads (override with env): real PLC `5020`, static decoy `5022`. The
live decoy's value comes from the MQTT topic `plant/telemetry` (not by polling
the decoy — that would show up in the honeypot log as a fake attacker). It
refreshes every 2 seconds.

## Note
This is a monitoring **view**, not part of the data path — closing it changes
nothing. The colours use a colourblind-safe palette (blue / aqua / yellow for the
three devices; green/amber/red reserved for status).
