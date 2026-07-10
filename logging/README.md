# Logging (Month 3)

Two tiers. On a 4 GB Mac, use the **light** one; the heavy one is optional.

## Light path — recommended, verified (no extra services)
The decoys already write structured JSON logs of every attacker action:
- `honeynet/modbus-decoy/decoy.log` — every read and write
- `honeynet/hmi/hmi_attempts.log` — every login attempt (with source IP)

Turn them into a report:
```bash
../.venv/bin/python ../analysis/summarize_attacks.py decoy.log hmi_attempts.log
```
Example output from a real attack run:
```
Modbus decoy activity: 9 events (7 reads, 2 writes)
  unauthorised writes: fc=6 addr=0 values=[1234],  fc=5 addr=0 values=[True]
HMI login brute-force: 16 attempts, 8 passwords, source 127.0.0.1
```
For the network-level view (who connected, from which IP), capture the attack
traffic (`sudo tcpdump ...`) and run Zeek — reuse the tools in `../listener/zeek`.

## Heavy path — optional full SIEM (Elasticsearch + Kibana + Filebeat)
Ships the same JSON logs into a searchable Kibana dashboard. Elasticsearch is
RAM-hungry (1–2 GB), so it is tight alongside the pipeline on a 4 GB Docker VM —
start it only when you have headroom, and consider stopping the pipeline first.
```bash
# make the decoys log into files this stack mounts:
DECOY_LOG="$(pwd)/../honeynet/modbus-decoy/decoy.log"   # when starting decoy.py
HMI_LOG="$(pwd)/../honeynet/hmi/hmi_attempts.log"       # when starting decoy_hmi.py

docker compose up -d
# open http://localhost:5601 -> Discover -> create a data view on 'filebeat-*'
docker compose down
```

> This project verified the light path (a 4 GB Docker VM can't comfortably run
> ELK next to the pipeline). The compose here is correct and ready when you have
> a machine with more memory, or when you stop the other stacks first.
