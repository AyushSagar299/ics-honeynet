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
- `honeynet/` - the decoys: the live one, a static one for comparison, an OPC UA decoy
  (the second protocol), Conpot, a fake HMI login, and a fleet of 8 fake devices with a
  threat dashboard. `honeynet/docker/` has the Dockerfile and compose file for running a
  decoy in a container
- `attacker/` - the five attack scripts I use to test the decoys, plus the OPC UA recon one
- `ai/` - the process-anomaly detection layer (trained on normal data only): the point-wise
  models and an LSTM autoencoder that works on windows
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

### The OPC UA decoy

This is the second protocol. It listens on 4840, says it is a SIMATIC S7-1500, and serves the
same four signals (level, temperature, pressure, pump) from the same simulated process. It
writes to the same `honeynet/fleet/connections.log` and `actions.log` as the fleet, so the
Threat Console picks it up with no extra setup. Modbus is untouched and still runs.

macOS or Linux:

```bash
.venv/bin/python honeynet/opcua-decoy/decoy_opcua.py
.venv/bin/python attacker/scripts/recon_opcua.py 127.0.0.1 4840
```

Windows:

```powershell
.venv\Scripts\python.exe honeynet\opcua-decoy\decoy_opcua.py
.venv\Scripts\python.exe attacker\scripts\recon_opcua.py 127.0.0.1 4840
```

If 4840 is taken, set `OPCUA_PORT` (and `OPCUA_BACKEND_PORT`, which is the localhost-only
server behind it) before starting it. `demo.sh` / `demo.bat` start and stop it for you.

### The anomaly detectors

These are run on their own, they do not need the pipeline:

```bash
.venv/bin/python ai/swat_detector.py
.venv/bin/python ai/temporal_detector.py          # the LSTM autoencoder, about 70s on cpu
```

Windows:

```powershell
.venv\Scripts\python.exe ai\swat_detector.py
.venv\Scripts\python.exe ai\temporal_detector.py
```

`temporal_detector.py` takes an optional CSV path, the same way `swat_detector.py` does, and
writes its table to `ai/temporal_results.txt`. It needs torch (CPU is fine, no GPU).

Each folder has its own README with more detail.

## Quick demo

This brings up the 8-device fleet, the OPC UA decoy on 4840, the static honeypot and the
threat dashboard in one go, then opens http://localhost:8100.

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

### Bot swarm (stress test)

Once the demo is up I can throw a swarm of bots at the fleet to see how it holds up. Start
the demo first, then run the swarm, then stop the demo.

macOS or Linux:

```bash
.venv/bin/python attacker/scripts/swarm.py 300
```

Windows:

```powershell
.venv\Scripts\python.exe attacker\scripts\swarm.py 300
```

The count is optional (default 300, clamped to 1-500). Every real connection only ever goes
to 127.0.0.1, there is no host argument on purpose. It does two things. First a REAL load:
it fires a few hundred bots at the fleet all at once, then reconnects to check the honeynet
survived, and prints how many devices still answered. Second, to show what a live deployment
would look like, it fills the threat dashboard with EXAMPLE global attacker IPs so the world
map lights up. Those IPs are demonstration data, not real captures, and the printed summary
keeps the two apart. If a manager asks: the survival result is real, the world map is a
demonstration of what real attackers would look like on an isolated network.

## Results

The main results are in `analysis/` (fig1 to fig3):

- the decoy follows the real plant closely, about 0.11% average error
- the live decoy's values move over time while the static one stays frozen
- the honeypot logs caught all of the Modbus reads/writes and the login attempts
- the anomaly-detection numbers are in `ai/swat_results.txt`, `ai/hai_results.txt` and
  `ai/temporal_results.txt`

The write-up is in `docs/report.md` and the analysis notebook is `analysis/analysis.ipynb`.

## Notes

- Most Docker images are arm64. Conpot and Kali are amd64 only, so they need
  `--platform linux/amd64` and Rosetta turned on.
- pymodbus is pinned to 3.6.9 because version 3.13 changed the server API. See
  `requirements.txt`.
- Port 502 needs sudo on a Mac, so on the laptop the servers use 5020, 5021 and 5022.
  Windows does not need admin for 502 but I kept the same high ports there so the two
  machines behave identically. In Docker they map back to 502.
