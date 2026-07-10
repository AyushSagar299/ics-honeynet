# ICS Honeynet — Active Defence for Industrial Environments

A Master's thesis project, built end-to-end on macOS (Apple Silicon) with Docker.

**The claim:** *a honeypot fed with live values from a digital twin is far harder to
fingerprint as fake than a traditional static honeypot, while the real equipment is
never exposed to the attacker.* This repo builds a small ICS lab, a live digital twin,
and decoys fed by that twin — then attacks them and measures the result.

## The three isolated networks

| Network      | What lives here                                | Range          |
|--------------|------------------------------------------------|----------------|
| Real lab     | water-tank PLC (Modbus), passive listener      | `10.10.0.0/24` |
| Honeynet     | live decoy, static decoy, Conpot, decoy HMI    | `10.20.0.0/24` |
| Attacker     | nmap + the 5 attack scripts (Kali optional)    | `10.30.0.0/24` |

The attacker can reach the honeynet but has **no path** to the real lab. Data flows one
way: real plant → twin → decoys.

## What's built (Stage A + Months 1–4)

```
ics-honeynet/
├── real-lab/process-simulator/  # Stage A: water-tank PLC + Modbus server   ✅
├── listener/                    # Month 1: passive DPI (Scapy) + Zeek logs   ✅
│   ├── scapy/  zeek/
├── bridge/                      # Month 2: pymodbus → MQTT publisher         ✅
├── twin/                        # Month 2: digital twin (+ InfluxDB writer)  ✅
├── pipeline/                    # Month 2: mosquitto + influxdb + grafana    ✅
├── honeynet/                    # Month 3: the decoys                        ✅
│   ├── modbus-decoy/            #   live decoy + static baseline
│   ├── conpot/                  #   Conpot (static, realistic fingerprint)
│   └── hmi/                     #   decoy HMI login honeypot
├── attacker/                    # Month 3: 5 attack scripts + container      ✅
├── logging/                     # Month 3: ELK stack (optional, heavy)       ✅
├── analysis/                    # Month 4: charts + Jupyter notebook         ✅
└── docs/                        # profiling note + thesis draft              ✅
```

## Quick start

```bash
# 0. one-time setup
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
brew install mosquitto zeek nmap        # system tools

# 1. the data services (MQTT, InfluxDB, Grafana)
cd pipeline && docker compose up -d && cd ..

# 2. the live pipeline (each in its own terminal)
.venv/bin/python real-lab/process-simulator/tank_plc.py     # the PLC        :5020
.venv/bin/python bridge/bridge.py                           # bridge → MQTT
.venv/bin/python twin/twin.py                               # the digital twin
#   open http://localhost:3000 (Grafana) to watch it live

# 3. the honeynet (each in its own terminal)
.venv/bin/python honeynet/modbus-decoy/decoy.py             # live decoy     :5021
.venv/bin/python honeynet/modbus-decoy/static_decoy.py      # static baseline:5022
.venv/bin/python honeynet/hmi/decoy_hmi.py                  # decoy HMI      :8090

# 4. attack it and see the results
.venv/bin/python attacker/scripts/run_all.py                # the 5 scenarios
cd analysis && ../.venv/bin/python collect_data.py && ../.venv/bin/python analysis.py
```

Each folder has its own README with details.

## Results (`analysis/`)

| Experiment | Result |
|------------|--------|
| Twin fidelity (fig1) | decoy tracks the real PLC to **0.11%** mean error |
| Believability (fig2) | live decoy moves (std **2.6**), static decoy frozen (std **0.0**) |
| Detection coverage (fig3) | **100%** of Modbus reads/writes + HMI logins captured |

The thesis draft is in `docs/thesis.md`; the analysis notebook is
`analysis/analysis.ipynb`.

## Notes

- **Apple Silicon:** most images are native arm64. Conpot / HoneyPLC / Kali are
  amd64-only — run them with `--platform linux/amd64` and Rosetta.
- **Version pins matter:** `pymodbus==3.6.9` (3.13 broke the classic server API),
  `paho-mqtt==2.1.0` (needs `CallbackAPIVersion.VERSION2`). See `requirements.txt`.
- **Ports on the laptop:** the real Modbus port 502 needs `sudo`, so the host tests use
  5020/5021/5022; in Docker these map back to 502.
