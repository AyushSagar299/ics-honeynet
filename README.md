# ICS Honeynet

It is a honeypot system for industrial control systems (ICS).

The problem it deals with is that most ICS honeypots are easy to spot, because their
sensor values never change. A skilled attacker reads a few registers, sees that nothing
moves, and knows it is a trap. To get around this I run a small simulated plant (a water
tank), keep a live copy of it called a Digital Shadow, and feed those live values into the
decoy devices. The decoys then show moving values like a real plant, so the attacker
cannot easily tell they are fake, and the real equipment is never touched.

It runs on macOS with Docker, and it also runs on Windows. The demo helpers are there
for both.

## Folder layout

- `real-lab/` - the water-tank PLC (a Modbus server) that produces the live values
- `listener/` - a passive listener (Scapy) that reads the Modbus traffic, plus Zeek
- `bridge/` - reads the PLC once a second and publishes the values to MQTT
- `twin/` - the Digital Shadow: keeps the live state and checks for anomalies
- `pipeline/` - the Docker services (Mosquitto, InfluxDB, Grafana)
- `honeynet/` - the decoys: the live one, a static one for comparison, Conpot, a fake HMI
  login, and a fleet of 8 fake devices with a threat dashboard. `honeynet/docker/` has the
  Dockerfile and compose file for running a decoy in a container
- `attacker/` - the five attack scripts I use to test the decoys
- `ai/` - the process-anomaly detection layer (trained on normal data only)
- `analysis/` - the result charts, the tools I wrote to measure how believable it is, the
  zero-egress safety test and the MITRE ATT&CK map
- `docs/` - the project write-up, the device-profiling note, the conceptual framing and the
  one-way safety invariant

`adversary_bot.py` and `live_view.py` sit at the top level, one drives an attack session
against the decoys and the other shows the live values in the terminal.

## How to run it

The commands below use `.venv/bin/python`, which is the macOS and Linux path. On Windows
the same scripts are run with `.venv\Scripts\python.exe` instead, nothing else changes.

Setup (once), macOS or Linux:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
brew install mosquitto zeek nmap
```

Setup (once), Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\pip.exe install -r requirements.txt
```

mosquitto, zeek and nmap have their own Windows installers. The fleet demo does not need
them.

Start the Docker services (MQTT, InfluxDB, Grafana):

```bash
cd pipeline && docker compose up -d && cd ..
```

Start the plant and the Digital Shadow, each in its own terminal:

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

## Quick demo

This brings up the 8-device fleet, the static honeypot and the threat dashboard in one go,
then opens http://localhost:8100.

macOS or Linux:

```bash
bash demo.sh        # or ./demo.sh if it is executable
bash stop_demo.sh   # when finished
```

Windows:

```
demo.bat
stop_demo.bat
```

The .bat and .ps1 files are the Windows half of this, so do not remove or rename them.

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
  Windows does not need admin for 502 but I kept the same high ports there so the two
  machines behave identically. In Docker they map back to 502.
