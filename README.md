# ICS Honeynet — Active Defence for Industrial Environments

A honeynet that mirrors a real ICS lab, built end-to-end on macOS (Apple Silicon)
with Docker Desktop. Master's thesis project.

**The idea:** build a *real* mini-factory in Docker first, capture its network
fingerprint, then build *decoy* services that mirror it. Because the decoys inherit
their fidelity from a real working system, attackers can't easily tell they're in a
trap — which produces better attack data.

## The four "worlds" (separate Docker networks)

| World        | What lives here                                  | Network        | Phase |
|--------------|--------------------------------------------------|----------------|-------|
| Real lab     | OpenPLC, Snap7, OPC UA server, Flask HMI         | `10.10.0.0/24` | 1     |
| Honeynet     | Conpot, HoneyPLC, decoy OPC UA, decoy HMI        | `10.20.0.0/24` | 3     |
| Attacker     | Kali Linux, nmap, Hydra, custom scripts          | `10.30.0.0/24` | 5     |
| Observer     | Filebeat + Elasticsearch + Kibana                | (honeynet)     | 4     |

The attacker can reach the honeynet, but **nothing** can reach the real lab.

## Folder layout

```
ics-honeynet/
├── real-lab/        # Phase 1 — the real mini-factory  (BUILT)
│   ├── openplc/     #   OpenPLC PLC (uses prebuilt image, no Dockerfile)
│   ├── snap7/       #   Siemens S7 simulator
│   ├── opcua/       #   OPC UA server
│   ├── hmi/         #   Flask HMI
│   ├── traffic/     #   eng-ws background traffic generator
│   └── docker-compose.yml
├── honeynet/        # Phase 3 — decoys                  (empty)
├── attacker/        # Phase 5 — Kali + attack scripts   (empty)
├── logging/         # Phase 4 — ELK stack               (empty)
└── analysis/        # Phase 2 & 7 — pcaps, Zeek, Jupyter (empty)
```

## Current status

- **Phase 0 — Set up the Mac:** done (Homebrew, Docker, Python, git, nmap, VS Code).
- **Phase 1 — Build the real lab:** files written, **not yet run**.
- Phases 2–7: not started.

## How to start the real lab (Phase 1.7)

```bash
# 1. Create the lab network (Phase 1.1) — only needed once
docker network create --subnet=10.10.0.0/24 real-lab-net

# 2. Build and start everything
cd ~/ics-honeynet/real-lab
docker compose up -d

# 3. Watch the background traffic generator
docker compose logs -f eng-ws
```

**Done when:** `eng-ws` prints `[Modbus] registers: [...]` every 5 seconds,
http://localhost:8080 shows the OpenPLC web UI, and http://localhost:5000 shows the HMI.

## Notes / likely first-run issues

- `version: '3.8'` in the compose file is obsolete in modern Docker Compose — the
  `WARN ... attribute version is obsolete` message is harmless.
- This is an **Apple Silicon (arm64)** Mac. If `openplc` won't start, it may be an
  amd64-only image — add `platform: linux/amd64` to that service and make sure
  *Use Rosetta for x86/amd64 emulation* is ticked in Docker Desktop → Settings → General.
- The `snap7`, `pymodbus`, and `asyncua` Python code is copied verbatim from the build
  guide. Library APIs change between versions, so expect to debug these when you run
  `docker compose up` — that's the hands-on part of Phase 1. See the build guide's
  "When you're stuck" section.

Build guide: `Desktop/480 Project/guide/Build_Guide_Step_By_Step.docx`
