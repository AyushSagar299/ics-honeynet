# Active Defence for Industrial Environments
## A honeypot fed with live values from a Digital Shadow

Ayush Sagar — Cuatroochenta — Master's internship

## Abstract

Industrial control systems run physical processes such as water, power and gas, and they
use old protocols that were designed without security. Honeypots are a common way to
watch attackers, but the usual ICS honeypots are easy to recognise because they serve
fixed values that never change. An attacker reads a few registers, sees that nothing
moves, and concludes it is a trap. This project tries to remove that weakness. I run a
small simulated process (a water tank) and serve it over Modbus, I keep a live copy of it
in a Digital Shadow, and I feed the shadow's live values into decoy devices. The decoys then
show the same moving values as the real process while the real equipment is never
exposed. I evaluate the system by attacking it and comparing the live decoy against a
static one. The live decoy follows the real plant to within about 0.11%, its values move
(standard deviation 2.6) while the static decoy stays frozen (standard deviation 0.0), and
the honeypot logs capture all of the application-layer attacks. The result is a honeypot
that is harder to fingerprint as fake, which means the attacker data it collects is more
useful.

## 1. Introduction

### 1.1 Context

Operational Technology (OT) is the computing that runs physical industrial processes. It
uses controllers called PLCs that read sensors and drive pumps, valves and heaters, and
these talk over industrial protocols such as Modbus. OT cares first about availability and
safety rather than confidentiality, and many of its protocols, Modbus in particular, have
no authentication and no encryption.

### 1.2 Problem

A honeypot is a fake system used to attract and study attackers. In ICS the most common
one is Conpot, but it serves values from a fixed template. Those values never change,
which is not how a real plant behaves, so an attacker can fingerprint the honeypot quickly
and the data that is collected has little value.

### 1.3 Contribution

The claim of this work is that a honeypot fed with live values from a Digital Shadow is much
harder to fingerprint as fake than a static honeypot, while the real equipment is never
exposed to the attacker.

### 1.4 Objectives

1. Build a realistic ICS process and serve it over a real industrial protocol.
2. Profile it passively with deep packet inspection, without disturbing it.
3. Build a live Digital Shadow of the process.
4. Build decoys fed by the shadow, and a static decoy to compare against.
5. Attack the system and measure fidelity, believability and detection.

## 2. State of the art

OT security is usually described with the Purdue model, which separates the plant into
levels. What matters here is that the field protocols, especially Modbus (port 502), have
no security at all, so anyone who can reach a device can read and write it.

For ICS honeypots the two well known ones are Conpot, a general ICS honeypot, and HoneyPLC,
which imitates a Siemens S7 PLC and came from a 2020 research paper. Both are useful but
they mostly serve static data, which is the weakness this project is about.

A digital shadow is a live software copy of a real system that is kept in sync with it, but
with the data flowing only one way, from the real system into the copy. This is different from
a digital twin, which is two-way and can send commands back to the real equipment (the
twin / shadow / model distinction comes from Kritzinger et al.). For a honeypot this one-way
property is essential: it is what makes the copy safe to expose, because nothing an attacker
does on the copy can travel back to the real plant. Using a one-way shadow to feed a honeypot
is the combination that, as far as I found, is not done by existing tools, and that is the gap
this project fills.

## 3. Methodology

I followed a "make it work, then make it real" approach: build a thin version of the whole
pipeline first, get one value flowing end to end, and only then deepen each part. The steps
were:

1. Build the process (a water-tank simulator) and serve it over Modbus. The first version
   is a plain pymodbus server; the real-PLC version uses OpenPLC.
2. Capture and read the traffic passively with Scapy and Zeek to profile the devices.
3. Poll the PLC and publish the values over MQTT into a Digital Shadow, store them in InfluxDB
   and show them in Grafana.
4. Feed the shadow's live state into the decoys, first over Modbus and later over OPC UA as
   well, and set up a static decoy and Conpot as baselines.
5. Attack the decoys and measure the results.

Everything runs in Docker, on a MacBook and also on a Windows laptop. The design uses three
separate networks so that the attacker can never reach the real plant.

## 4. System design

### 4.1 Architecture

There are three isolated networks: the real lab (the PLC and the process), the honeynet
(the decoys), and the attacker. The attacker can reach the honeynet but has no path to the
real lab. The data only flows one way, from the real plant to the shadow to the decoys, so a
write to a decoy can never reach the real PLC.

It is worth saying why the decoys still speak Modbus, since Modbus has no authentication and
no encryption. That is the point: it is the lure. An attacker who finds an open Modbus port
will try to read and write it, and that attempt is exactly the behaviour I want to record, so
making the decoy harder to talk to would only make it less attractive. The safety does not
come from the protocol, it comes from the one-way isolation, which is what stops anything the
attacker does from reaching the real plant. So a second protocol was added next to Modbus
(OPC UA, section 6.4), not instead of it.

### 4.2 The data pipeline

The pipeline is: tank_plc, then the bridge which polls it once a second, then MQTT
(Mosquitto), then the shadow, then InfluxDB and Grafana. The shadow's state is also sent to the
decoys. The passive listener (Scapy and Zeek) and the honeypot logs run alongside.

### 4.3 The process and the registers

The process is a water tank with level, temperature and pressure, plus pump, heater and
valve flags. The values are stored in Modbus holding registers HR0 to HR5. The analog
values are multiplied by 10 so they keep one decimal place inside an integer register. A
simple rule keeps the level between 40% and 80%.

## 5. Implementation

The system is written in plain Python. The main parts are:

- The process simulator and PLC (`real-lab/process-simulator/tank_plc.py`): a physics
  thread and a pymodbus server on port 502 (5020 on the laptop).
- The passive listener (`listener/`): a read-only Scapy sniffer that decodes Modbus into
  plain text, and Zeek which produces JSON logs. The device profiling is written up in
  `docs/device-profiling-note.md`.
- The bridge (`bridge/bridge.py`): a pymodbus client that publishes to MQTT with paho-mqtt.
- The Digital Shadow (`twin/twin.py`): an MQTT subscriber that holds the live state, does a
  simple expected-value check for anomalies, and writes to InfluxDB.
- The decoys (`honeynet/`): the live decoy is a pymodbus server whose registers are fed by
  the shadow, and it logs every read and write. There is also a static decoy and Conpot as
  baselines, and a fake HMI login page that records the passwords that are tried.
- The OPC UA decoy (`honeynet/opcua-decoy/decoy_opcua.py`): an asyncua server that answers on
  port 4840 with a Siemens S7-1500 identity and four live variables. The asyncua server
  itself only binds localhost and a small relay owns the public port, which is how the
  source IP gets into the log. Reads and writes are logged by subclassing asyncua's
  internal session object, since the library has no read callback of its own.
- The attacker scripts (`attacker/`): recon, enumeration, unauthorised write, brute force,
  and a replay/robustness test, plus `recon_opcua.py` for the OPC UA decoy.
- The anomaly detection (`ai/`): Isolation Forest, One-Class SVM and a PCA reconstruction,
  trained on normal data only with a temporal split, on SWaT/HAI-format data, and an LSTM
  autoencoder (`ai/temporal_detector.py`) that scores a window instead of a single sample.
- The safety checks (`analysis/zero_egress_test.py`, `analysis/attack_mitre_map.py`): one
  proves nothing reaches the plant, the other maps what the attacker did onto MITRE ATT&CK
  for ICS.

A few things I learned by actually running it, which are worth noting:

- pymodbus 3.13 changed the server API and broke the old code, so the project pins
  pymodbus 3.6.9.
- The pymodbus context offsets addresses by one, so the register values have to be written
  with setValues(3, 0, ...) rather than passed to the datablock when it is created.
- paho-mqtt version 2 needs the new CallbackAPIVersion.VERSION2 argument.

## 6. Evaluation

The three main experiments are in `analysis/analysis.ipynb`.

### 6.1 Shadow fidelity

Reading the real PLC and the shadow-fed decoy at the same time, the decoy follows the real
plant with a mean level error of about 0.11%, and the lag is smaller than the 0.5 second
sampling interval. The two curves are almost on top of each other (Figure 1). So the shadow
is a faithful copy of the plant.

### 6.2 Believability, live versus static

Reading each decoy twelve times, the live decoy's level has a standard deviation of 2.6, so
it clearly moves, while the static decoy's is 0.0, so it is frozen (Figure 2). Under the
same reconnaissance an attacker sees the live decoy change and the static one stand still,
which is the whole point of the project.

### 6.3 Detection coverage

The honeypot logs captured all of the Modbus reads and writes and all of the HMI login
attempts, for example an unauthorised write of the value 1234 to register 0 and sixteen
brute-force logins with their source IPs (Figure 3). Plain port scans are not
application-layer events, so they are captured by the network sensor (Zeek) rather than by
the honeypot log.

### 6.4 Fingerprinting tells, and the second protocol

`analysis/honeypot_detector.py` is the other side of the believability test: I play the
attacker and count the "tells" that give a decoy away. One of the tells it lists is that the
device only answers Modbus, because a real PLC of this size normally exposes more than one
service. To close that one I added an OPC UA decoy on port 4840 (section 5). It advertises a
SIMATIC S7-1500 identity and serves the same four signals as the water-tank device (level,
temperature, pressure, pump) driven by the same simulated process, so the two protocols tell
one consistent story about the plant instead of contradicting each other. An attacker write
is taken into the process model rather than snapped back, so a silly value like 999 drifts
back into range over the next few seconds the way a real loop would pull it back.

The logging is the same as the Modbus fleet's, so nothing new had to be built for it: reads,
writes and bare port scans land in `connections.log` and `actions.log`, and the Threat Console
now shows nine devices instead of eight. That needed one small fix in `dashboard.py`, which
had been counting only the devices listed in `devices.py` and was silently dropping the OPC
UA reads, writes and probes from the KPIs.

Two honest notes on the tell count. First, the "Only Modbus is exposed" line in
`honeypot_detector.py` is still appended unconditionally, so the script keeps printing it: the
plant no longer has that weakness, but until that check actually probes 4840 the number it
prints is one higher than it should be. That is a fix owed to the detector script, not to the
honeynet. Second, only reads and writes of the four plant variables are logged, not the
housekeeping requests the OPC UA stack makes when a client connects, since those say nothing
about what the attacker wanted.

### 6.5 Clustering attacker sessions

As a smaller extra experiment I used KMeans to group attacker sessions by behaviour, which
separates scanners from tamperers from brute-forcers (Figure 4). With more real attack data
this would separate attacker types more clearly.

### 6.6 Process-anomaly detection

The `ai/` layer is evaluated separately, because it works on the process telemetry rather
than on the decoy traffic. The models are trained on normal data only and tested on a later
window, so they never see the attacks beforehand. The numbers are in `ai/swat_results.txt`
(SWaT-format data) and `ai/hai_results.txt` (the real HAI files). On the SWaT-format data
the PCA reconstruction is clearly the best of the three (PR-AUC 0.80), and on the real HAI
data all three are much weaker (PR-AUC 0.05 to 0.28), which is the honest result and shows
how much harder real plant data is.

Those three models all judge one sample at a time. A slow drift or a stuck sensor can look
perfectly normal in any single sample and only stands out as a trajectory, so I added a
temporal model beside them, an LSTM autoencoder that reconstructs a 30-sample window
(`ai/temporal_detector.py`, table in `ai/temporal_results.txt`). It reuses the same split, the
same scaler fitted on train only, the same 99.5th-percentile threshold rule and the same
`evaluate()` as `swat_detector.py`, and windows are built inside train and inside test
separately so none of them straddles the boundary. Each window is scored at its last
timestamp, so the detector only ever uses past samples.

On the SWaT-format file it won, but not cleanly. Over three seeds it got PR-AUC 0.74 on
average (range 0.71 to 0.78) against 0.56 for PCA on exactly the same columns. Against that,
it is slower to fire, 114 to 148 seconds to the first alarm versus 93 for PCA, because the
reconstruction error only builds up once a whole window is bad; it catches 3 of the 4 attack
segments and misses the same stuck-sensor one PCA misses; and with only four segments the
spread between seeds is not much smaller than the gap itself, so I would not claim this as a
settled win. One-Class SVM is the only model that catches all four, and it does that at
around 7,500 false alarms a day, which no operator would accept.

Building it also turned up a problem with the 0.80 above, which I am reporting rather than
quietly fixing. `swat_detector.py` keeps every numeric column, and `ai/swat_like.csv` has a
"Timestamp" column that is really just a row counter. It only ever increases, so in the test
half it sits outside everything the scaler saw during training and becomes a steady ramp that
flatters the score. With that column dropped, PCA falls from PR-AUC 0.80 to 0.56, and the
window model goes the other way, 0.20 with it against 0.78 without, because a monotonic ramp
is poison for a model that looks at trajectories. `temporal_detector.py` therefore drops
strictly increasing counter columns and runs all four models on the same 10 sensors, which is
why its PCA row disagrees with `ai/swat_results.txt`. The fair comparison is the 0.56 one.
This does not affect the HAI numbers, where the time column is dropped by name, and it would
not affect the real SWaT file, where the timestamp is a date string.

## 7. Conclusions

The system supports the claim. A decoy fed by the Digital Shadow passes the test an attacker
actually uses, which is whether the values move, while the static honeypot gives itself
away. At the same time the real equipment is never exposed, and the honeypot records the
full application-layer attack.

There are limitations, which are worth stating honestly. The process is a single water tank,
and although the decoys now speak Modbus and OPC UA, that is still only two protocols and one
kind of plant. Conpot runs under emulation and its default template made
clean register reads awkward, so I used a matched static decoy as the controlled baseline.
The full ELK stack was too heavy to run on a 4 GB Docker setup alongside the pipeline, so I
used a lighter log-analysis path instead. The attack traffic comes from my own scripts in
an isolated lab, not from real attackers on the internet.

For future work I would add an S7 decoy and DNP3 (using Grid-Watch and Caldera for OT), make
the honeypot detector actually probe the OPC UA port instead of assuming Modbus is the only
service, regenerate the `ai/swat_results.txt` numbers without the counter column, run the full
three-network isolation in Docker, expose the honeynet to real traffic, and grow the dataset
for the anomaly-detection part.

## References

To be formatted in the required citation style. The main sources are:

- Modbus Application Protocol Specification, Modbus Organization.
- Conpot, an ICS/SCADA honeypot (mushorg / The Honeynet Project).
- E. López-Morales et al., "HoneyPLC: A Next-Generation Honeypot for Industrial Control
  Systems", ACM CCS 2020.
- MITRE ATT&CK for ICS, MITRE Corporation.
- 4SICS ICS lab network captures, NETRESEC.
- Digital twin and digital shadow surveys (Kritzinger et al.), for the twin / shadow / model taxonomy.
- iTrust SWaT / WADI datasets, Singapore University of Technology and Design (for the
  anomaly-detection part).
