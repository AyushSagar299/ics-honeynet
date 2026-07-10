# Active Defence for Industrial Environments
### A honeypot fed with live values from a digital twin

**Author:** Ayush Sagar · **Company:** Cuatroochenta · **Type:** Master's thesis

> This is the working draft. It follows the standard structure (Introduction,
> State of the Art, Methodology, Design, Implementation, Evaluation, Conclusions).
> The technical chapters and the results are already filled in from the built
> system; expand the prose in your own words as you go. Figures are in
> `analysis/` (fig1–fig4).

---

## Abstract

Industrial control systems (ICS) run physical processes — water, power, gas — using
old protocols that have no security. Honeypots are a common way to watch attackers,
but ordinary ICS honeypots are easy to spot: they serve fixed, unchanging values, so
a skilled attacker reads a few registers, sees nothing ever moves, and knows it is a
trap. This work removes that weakness. I build a small real process (a simulated water
tank driven by a real PLC runtime), copy its live state into a **digital twin**, and
feed that live state into decoy devices. The decoys therefore show the same moving
values as the real plant, while the real equipment is never exposed. I evaluate the
system by attacking it and comparing the live decoy against a static one: the live
decoy tracks the real plant to within **0.11%**, its values move (std 2.6) while the
static decoy stays frozen (std 0.0), and the honeypot logs capture 100% of the
application-layer attacks. The result is a honeypot that is much harder to fingerprint
as fake, producing more realistic attacker data.

## 1. Introduction

### 1.1 Context
Operational Technology (OT) is the computing that runs physical industrial processes.
It uses controllers (PLCs) that read sensors and drive pumps, valves and heaters, and
they talk over industrial protocols such as Modbus. OT prioritises availability and
safety over confidentiality, and many of its protocols — Modbus in particular — have
no authentication or encryption at all.

### 1.2 Problem
A honeypot is a fake system used to attract and study attackers. In ICS, honeypots
like Conpot are widely used, but they serve values from a fixed template. Those values
never change, which is unrealistic — a real plant is always moving — so an attacker can
fingerprint the honeypot quickly and the collected data is of little value.

### 1.3 The claim (contribution)
> A honeypot fed with live values from a digital twin is far harder to fingerprint as
> fake than a traditional static honeypot, while the real equipment is never exposed to
> the attacker.

### 1.4 Objectives
1. Build a realistic ICS process and expose it over a real industrial protocol.
2. Passively profile it (deep packet inspection) without disturbing it.
3. Build a live digital twin of the plant.
4. Build decoys fed by the twin, plus a static baseline to compare against.
5. Attack the honeynet and measure fidelity, believability and detection.

## 2. State of the Art

- **ICS/OT security.** The Purdue model, why OT differs from IT, and why Modbus (port
  502, no auth) is both common and insecure. [expand with references]
- **Honeypots for ICS.** Conpot (a general ICS honeypot) and HoneyPLC (a Siemens S7
  honeypot from a 2020 paper). Both are valuable but serve mostly static data.
- **Digital twins.** A digital twin is a live software copy of a real system kept in
  sync with it. Twins are used for monitoring and prediction; using one to *feed a
  honeypot* is the novel combination here.
- **The gap.** Existing ICS honeypots are static and therefore fingerprintable. No
  common tool feeds a honeypot with a live digital twin of a real process. That gap is
  what this thesis fills.

## 3. Methodology

The guiding principle is *make it work, then make it real*: build a thin version of the
whole pipeline first, then deepen it. The steps:

1. Build a real process (water-tank simulator) served over Modbus (Stage A: a pymodbus
   server; Stage B: OpenPLC).
2. Passively capture and dissect the traffic (Scapy + Zeek) to profile the devices.
3. Poll the PLC and publish telemetry (MQTT) into a digital twin, store it (InfluxDB)
   and visualise it (Grafana).
4. Feed the twin's live state into decoys; build a static decoy and set up Conpot as
   baselines.
5. Attack the decoys and measure the results.

Everything runs in Docker on a MacBook (Apple Silicon), split into three isolated
networks so the attacker can never reach the real plant.

## 4. System Design

### 4.1 Architecture
Three isolated Docker networks:
- **Real lab** (`10.10.0.0/24`) — the PLC and the real process.
- **Honeynet** (`10.20.0.0/24`) — the decoys.
- **Attacker** (`10.30.0.0/24`) — Kali / the attack scripts.

The attacker can reach the honeynet but has **no path** to the real lab. Data flows one
way only: real plant → twin → decoys. An attacker writing to a decoy can never reach the
real PLC.

### 4.2 The data pipeline
`tank_plc → bridge (poll 1s) → MQTT (Mosquitto) → twin → InfluxDB → Grafana`, with the
twin's state also fed to the decoys. A passive listener (Scapy + Zeek) and the honeypot
logs run alongside.

### 4.3 The process and register map
A water tank: level, temperature, pressure, and pump/heater/valve flags. Stored in
Modbus holding registers HR0–HR5 (the analog values ×10 to keep one decimal in an
integer register). A simple controller keeps the level between 40% and 80%.

## 5. Implementation

Written in plain Python. Key components:
- **Process simulator + PLC** (`real-lab/process-simulator/tank_plc.py`): physics thread
  + a pymodbus server on port 502/5020.
- **Passive DPI listener** (`listener/`): a read-only Scapy sniffer that decodes Modbus
  in plain text, plus Zeek producing JSON `modbus.log`. Device profiling in
  `docs/device-profiling-note.md`.
- **Bridge** (`bridge/bridge.py`): pymodbus client → paho-mqtt publisher.
- **Digital twin** (`twin/twin.py`): MQTT subscriber holding live state + an
  expected-value check (the anomaly seed) + InfluxDB writer. Grafana dashboard.
- **Live decoy** (`honeynet/modbus-decoy/decoy.py`): a pymodbus server whose registers
  are fed from the twin; it logs every attacker read/write. **Static decoy** and
  **Conpot** as baselines. A **decoy HMI** login honeypot logs credential attempts.
- **Attacker** (`attacker/`): five scripts — recon, enumeration, unauthorised write,
  brute-force, replay/robustness.

**Engineering notes (things learned by actually running it):**
- pymodbus 3.13 broke the classic server API, so the project pins `pymodbus==3.6.9`.
- `ModbusSlaveContext` offsets addresses by 1, so register values must be written with
  `setValues(3, 0, ...)` rather than passed to the datablock constructor.
- paho-mqtt 2.x requires `CallbackAPIVersion.VERSION2`.

## 6. Evaluation

Three experiments, all measured on the running lab (`analysis/analysis.ipynb`).

### 6.1 Twin fidelity (fig1)
Sampling the real PLC and the twin-fed decoy together, the decoy tracks the real plant
with a **mean level error of 0.11%** and a lag below the 0.5 s sampling resolution. The
two curves are visually almost identical (Figure 1). The twin is a faithful copy.

### 6.2 Believability — live vs static (fig2)
Reading each decoy 12 times: the **live decoy's** level has standard deviation **2.6**
(it moves, like a real plant), while the **static decoy's** is **0.0** (frozen). Under
the same reconnaissance, an attacker sees the live decoy change and the static one stand
still (Figure 2). This directly supports the central claim.

### 6.3 Detection coverage (fig3)
The honeypot's application-layer logs captured **100%** of the Modbus reads, Modbus
writes and HMI login attempts (e.g. an unauthorised write of `1234` to register 0, and
16 brute-force logins with source IPs). Pure port scans are not application-layer events
and are captured by the network sensor (Zeek) instead (Figure 3).

### 6.4 (Optional) Clustering attacker sessions (fig4)
A small KMeans example groups attacker sessions by behaviour (scanners / tamperers /
brute-forcers); with more collected sessions this separates attacker types.

## 7. Conclusions

The system demonstrates the claim: a digital-twin-fed decoy is indistinguishable from
the real plant on the test an attacker actually uses (do the values move?), while a
static honeypot gives itself away, and the real equipment is never exposed. The honeypot
also captures the full application-layer attack.

**Limitations (be honest):**
- One simple process (a water tank) and one main protocol (Modbus).
- Conpot runs under emulation; its default template made clean register reads awkward,
  so a matched static decoy was used as the controlled baseline.
- The full ELK SIEM was not run (a 4 GB Docker VM is too small alongside the pipeline);
  the lighter JSON-log analysis path was used instead.
- Attack data is from self-run scenarios, not real internet attackers.

**Future work:** add S7 and OPC UA decoys (and HoneyPLC), add DNP3 (Grid-Watch /
Caldera for OT), run the full three-network isolation in Docker, expose the honeynet to
real traffic, and grow the dataset for the machine-learning chapter.

## References
[To add: Modbus spec; Conpot; the HoneyPLC paper; digital-twin surveys; MITRE ATT&CK for
ICS; any OT/ICS dataset used.]
