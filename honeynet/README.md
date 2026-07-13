# The honeynet (Month 3) — your contribution

The honeynet is the trap. It holds fake devices (decoys) that attackers can
poke at while the real plant stays hidden and safe. The novel part of this
project is **how** the main decoy gets its data.

## The three decoys

| Decoy | Port (laptop) | Data source | Point |
|-------|---------------|-------------|-------|
| **Live Modbus decoy** (`decoy.py`) | 5021 | the digital twin (live) | the contribution — moves like a real plant |
| **Static decoy** (`static_decoy.py`) | 5022 | a frozen snapshot | the matched baseline to beat |
| **Conpot** (`conpot/`) | 5502 | a fixed template | a real, well-known honeypot (realistic fingerprint, static data) |

All three speak Modbus on the **same register map**, so an attacker meets three
"identical" devices — but only the live one behaves like a real plant.

## The result (this is the project evidence)
Reading each device twice, a few seconds apart:
```
real PLC        MOVING   (level 76.0% -> 77.5%)
LIVE decoy      MOVING   (level 77.5% -> 79.0%)   <- mirrors the real plant
STATIC decoy    FROZEN   (level 50.0% -> 50.0%)   <- obvious trap
```
The live decoy is indistinguishable from the real plant; the static ones give
themselves away. That is the claim, demonstrated.

## Safety — the one-way mirror (verified)
Data flows **twin -> decoy only**. When an attacker wrote `9999` into the live
decoy, the real PLC was completely unaffected (it is a separate program on a
separate network). An attacker can read and "control" the decoy freely and never
touch the real equipment.

## Attacker logging
`decoy.py` writes a JSON line for every read and write a client makes (a client
here = an attacker), e.g.:
```json
{"ts": "2026-07-07T03:48:05", "event": "write", "fc": 6, "address": 0, "values": [9999]}
```
This is the detection evidence. (The *who* — the attacker's IP — is added later
by Zeek watching the honeynet network.)

## How to run
```bash
# needs the pipeline (mosquitto) up and the real PLC + bridge publishing telemetry
../.venv/bin/python modbus-decoy/decoy.py            # live decoy   (port 5021)
../.venv/bin/python modbus-decoy/static_decoy.py     # static decoy (port 5022)
cd conpot && docker compose up -d                    # Conpot       (port 5502)
```

## Next (Month 3 continued)
Stand up the Kali attacker on its own isolated network, run the five attack
scenarios against these decoys (live vs static), and ship the logs to
Elasticsearch/Kibana. Then analyse in JupyterLab.
