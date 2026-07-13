# ICS Honeynet

My master's internship project for Cuatroochenta. It is a honeypot system for
industrial control systems (ICS).

The problem it deals with is that most ICS honeypots are easy to spot, because their
sensor values never change. A skilled attacker reads a few registers, sees that nothing
moves, and knows it is a trap. To get around this I run a small simulated plant (a water
tank), keep a live copy of it called a digital twin, and feed those live values into the
decoy devices. The decoys then show moving values like a real plant, so the attacker
cannot easily tell they are fake, and the real equipment is never touched.

Everything runs on macOS with Docker.

## Folder layout

- `real-lab/` - the water-tank PLC (a Modbus server) that produces the live values
- `listener/` - a passive listener (Scapy) that reads the Modbus traffic, plus Zeek
- `bridge/` - reads the PLC once a second and publishes the values to MQTT
- `twin/` - the digital twin: keeps the live state and checks for anomalies
- `pipeline/` - the Docker services (Mosquitto, InfluxDB, Grafana)
- `honeynet/` - the decoys: the live one, a static one for comparison, Conpot, a fake HMI
  login, and a fleet of 8 fake devices with a threat dashboard
- `attacker/` - the five attack scripts I use to test the decoys
- `analysis/` - the result charts and the tools I wrote to measure how believable it is
- `docs/` - the project write-up and the device-profiling note

## How to run it

Setup (once):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
brew install mosquitto zeek nmap
```

Start the Docker services (MQTT, InfluxDB, Grafana):

```bash
cd pipeline && docker compose up -d && cd ..
```

Start the plant and the twin, each in its own terminal:

```bash
.venv/bin/python real-lab/process-simulator/tank_plc.py
.venv/bin/python bridge/bridge.py
.venv/bin/python twin/twin.py
```

Grafana is at http://localhost:3000. Then start the decoys and attack them:

```bash
.venv/bin/python honeynet/modbus-decoy/decoy.py
.venv/bin/python honeynet/modbus-decoy/static_decoy.py
.venv/bin/python attacker/scripts/run_all.py
```

Each folder has its own README with more detail.

## Results

The main results are in `analysis/` (fig1 to fig3):

- the decoy follows the real plant closely, about 0.11% average error
- the live decoy's values move over time while the static one stays frozen
- the honeypot logs caught all of the Modbus reads/writes and the login attempts

The write-up is in `docs/report.md` and the analysis notebook is `analysis/analysis.ipynb`.

## Notes

- Most Docker images are arm64. Conpot and Kali are amd64 only, so they need
  `--platform linux/amd64` and Rosetta turned on.
- pymodbus is pinned to 3.6.9 because version 3.13 changed the server API. See
  `requirements.txt`.
- Port 502 needs sudo on a Mac, so on the laptop the servers use 5020, 5021 and 5022.
  In Docker they map back to 502.
