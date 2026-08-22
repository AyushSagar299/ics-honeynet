# Real lab — the plant side of the honeynet

This folder is the **real plant**: one PLC and the small network of things that
would surround a real PLC on a real site. Everything else in the project (the
listener, the bridge, the twin, the decoys) treats this as the ground truth.

The important idea: every service here serves **live values from the same
plant**. The tank PLC is the single source of truth, and the S7 and OPC UA
faces just mirror it, so an attacker who cross-checks the protocols sees one
consistent, moving story — the same property the decoys imitate.

```
                real-lab-net  (10.10.0.0/24, external)

   tank-plc      10.10.0.10:502    Modbus TCP — the PLC (source of truth)
   snap7-sim     10.10.0.11:102    S7comm — DB1 mirrors the PLC registers
   opcua-server  10.10.0.12:4840   OPC UA — gateway, mirrors + setpoint writes
   flask-hmi     10.10.0.13:5000   the operator's web HMI
   eng-ws        10.10.0.20        engineering workstation (background traffic)
```

The addresses are fixed on purpose: `docs/device-profiling-note.md` and the
Zeek sample logs profile the plant by IP (`.10` = the PLC, `.20` = the
workstation), so they must not move between runs.

## The pieces

- `process-simulator/` — the tank PLC itself: the water-tank physics plus a
  Modbus server (its own README has the full register map, HR0–HR5 frozen).
- `snap7/` — reads the PLC once a second and serves the same values as S7
  data block DB1 (the 4SICS capture showed real attackers love S7).
- `opcua/` — a Modbus → OPC UA gateway: a browsable `WaterTank` node tree
  with live values, and two *writable* setpoint nodes that really land in the
  PLC, so OPC UA is a second genuine control path.
- `hmi/` — a plain Flask page that shows the plant state and refreshes every
  2 s; `/status` gives the same as JSON.
- `traffic/` — plays the operators: jittered Modbus/OPC UA/HTTP polling and,
  every few minutes, a small legitimate setpoint write. A silent network (or
  one that polls at exactly 5.000 s forever) is its own tell.

## How to run it

```bash
docker network create --subnet 10.10.0.0/24 real-lab-net   # once
docker compose up -d --build
docker compose logs -f tank-plc     # live level/temp/pressure lines = alive
```

Quick checks from the host, one per protocol:

```bash
# Modbus — the values change between runs
MODBUS_PORT=502 ../.venv/bin/python process-simulator/read_test.py

# HMI — open http://localhost:5001 (5001 because macOS AirPlay holds 5000)
curl -s http://localhost:5001/status

# OPC UA — any client on opc.tcp://localhost:4840/plant/, browse WaterTank
# S7 — any S7 client, DB1 (layout in snap7/server.py)
```

Stop it with `docker compose down` (the network stays, which is the point of
it being external — listener containers can attach to it).

## Laptop mode (no Docker)

Every service takes its targets from env vars, defaulting to the Docker IPs.
For quick work without Docker, run the tank on port 5020 as usual and point
the others at it, e.g.:

```bash
../.venv/bin/python process-simulator/tank_plc.py                # terminal 1
PLC_HOST=127.0.0.1 PLC_PORT=5020 HMI_PORT=5001 \
  ../.venv/bin/python hmi/app.py                                 # terminal 2
```

(`python-snap7` is in the project requirements too, so the S7 mirror also runs
on the laptop — use `S7_PORT=10102`, since 102 needs sudo like 502 does.)

## Stage B — OpenPLC

The plan from the research log stands: later, OpenPLC can take over as the
PLC with real ladder logic, and nothing downstream changes because the Modbus
side stays the same. It is parked behind a compose profile
(`docker compose --profile stage-b up -d openplc`) because of two known
quirks: the image is x86 (Rosetta on the Mac), and the default template
serves Modbus on 5020 inside the container, not 502.

## Ideas to take it further

- a second PLC on the network (e.g. a dosing pump) so the plant is not a
  single device — and the fleet decoys then have a second thing to imitate
- a historian container that logs to the InfluxDB in `pipeline/`, because a
  plant network without a historian polling is slightly too quiet
- a tcpdump sidecar on `real-lab-net` writing rotating pcaps, so every run
  produces capture material for the Zeek/listener chapters
- DNP3 as a third protocol (Zeek parses it natively, unlike S7)
- fix the network-level tells the research log found (MAC vendor prefix, OS
  fingerprint) with container-level settings
