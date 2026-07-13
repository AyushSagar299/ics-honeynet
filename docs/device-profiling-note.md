# Device Profiling Note — Month 1 deliverable

**Goal:** describe every device on the network using *only* what the captured
traffic shows — no scanning, no probing, no packets sent. This is "non-intrusive
device profiling", one of the internship learning outcomes.

**Method:** the traffic was recorded passively (`tcpdump` / a Scapy sniffer that
only listens) and then read back offline with two tools: `dpi_listener.py`
(prints each Modbus message in plain text) and Zeek (writes `conn.log` and
`modbus.log`). Nothing was ever sent to the devices.

> The numbers below come from the sample capture (`listener/scapy/sample_modbus.pcap`).
> When the real lab is running, capture live and re-run the same two tools —
> the note is filled in the same way.

---

## Devices discovered

| IP address | Port | Role (inferred) | Why we think so |
|------------|------|-----------------|-----------------|
| `10.10.0.10` | 502 | **PLC** (Modbus server / outstation) | It *listens* on the Modbus port 502 and *answers* read and write requests. |
| `10.10.0.20` | 51000 | **Engineering workstation / HMI** (Modbus master) | It *opens* the connection and *drives* it — it asks the questions. |

`conn.log` confirms a single Modbus connection:
`10.10.0.20:51000 -> 10.10.0.10:502  service=modbus  duration=7.02s`.

---

## Profile of the PLC (`10.10.0.10`)

- **Protocol:** Modbus TCP, unit id `1`.
- **Function codes seen:** `0x03` Read Holding Registers, `0x06` Write Single Register.
- **Registers in use (inferred from the values):**

  | Register | Value seen | Looks like |
  |----------|------------|------------|
  | HR0 | 502 → 466 (falling) | water **level** (%×10), draining |
  | HR1 | 235 → 250 (rising) | water **temperature** (°C×10), heating |
  | HR2 | 50 → 46 | **pressure** (bar×10), tracks the level |
  | HR3 | 1 | **pump** on/off |
  | HR4 | 1 | **heater** on/off |
  | HR5 | 1 | **valve** on/off |

  The mix of slowly-drifting analog values and 0/1 flags is a classic small
  process controller — here, a water tank.

## Profile of the workstation (`10.10.0.20`)

- **Behaviour:** polls the PLC by reading registers 0–5 **once per second**
  (transactions 1–6 at 03:00:01 … 03:00:06 — a steady automated loop, not a human).
- **One write:** transaction 7 writes register 10 = 1 (a setpoint / command).
- This periodic read + occasional write is exactly how an HMI or SCADA poller
  behaves.

---

## Security observations (relevant to the project)

- **No authentication, no encryption.** Modbus has none. The write to register 10
  was accepted with no login and no check — anyone who can reach port 502 could
  do the same. This is *why* the honeynet is interesting: an attacker can read and
  "control" a decoy freely, while the real PLC stays untouched.
- **Everything is readable in the clear.** Passive listening alone reveals the
  register map, the polling rate and the control commands — no need to touch the
  device. That is both the power of DPI and the risk in a real plant.

---

## How to reproduce
```bash
# 1. capture (real lab, port 502) — from inside a listener container, or:
sudo tcpdump -i lo0 -w capture.pcap 'tcp port 5020'     # Stage A on the laptop

# 2. plain-text DPI
../listener/scapy && python dpi_listener.py capture.pcap 5020

# 3. structured JSON logs
../listener/zeek && zeek -r capture.pcap modbus-ports.zeek LogAscii::use_json=T
```
