# Research Log

Three lines per session: what I did, what I learned, what's next.
(Habit from the roadmap, Part 6. Keep it honest and short.)

---

## 2026-06-10 — Phase 0 + Phase 1 scaffold

- **Did:** Verified Mac setup (Docker, Python, git, nmap installed; zeek + Wireshark
  still to do for Phase 2). Created the `ics-honeynet` folder structure and wrote all
  Phase 1 real-lab files (docker-compose + Dockerfiles + server scripts).
- **Learned:** The build guide's Dockerfiles used single quotes in `CMD` (`['python',
  'server.py']`), which Docker can't parse as exec form — fixed to double quotes.
- **Next:** Run Phase 1.7 — `docker network create real-lab-net`, then
  `docker compose up -d`, and debug any library/arch issues until `eng-ws` shows traffic.

---

## 2026-07-07 — Stage A: water-tank PLC works

- **Did:** Wrote `real-lab/process-simulator/tank_plc.py` — a water-tank physics
  simulator + Modbus TCP server in one file — plus `read_test.py`. Ran it and a
  client read live, changing values (level draining, temp rising with heater).
  Stage A of the "make it work, then make it real" plan is proven.
- **Learned:** pymodbus 3.13 broke the classic server API (renamed
  `ModbusSlaveContext`→`ModbusDeviceContext`, `slaves=`→`devices=`, context no
  longer subscriptable, datastore start address can't be 0). Pinned
  `pymodbus==3.6.9` (classic API, matches ICS tutorials/Conpot/HoneyPLC). venv at
  `.venv`. Port 5020 on the laptop (502 needs sudo; Docker will use 502).
- **Next:** Month 1 proper — either a small Flask HMI to see the tank in a browser,
  or the passive listener (Scapy) to capture and dissect the Modbus traffic.

---

## 2026-07-07 — Part 2: passive DPI listener works (Scapy + Zeek)

- **Did:** Built `listener/scapy/dpi_listener.py` (passive, read-only Modbus DPI
  that prints reads/writes in plain English), `make_sample_pcap.py` (generates a
  real-Modbus-bytes capture so the tools can be tested without sudo/Docker), and
  `listener/zeek/run_zeek.sh` (+ `modbus-ports.zeek`) producing JSON `modbus.log`
  and `conn.log`. Wrote the Month 1 deliverable `docs/device-profiling-note.md`.
  Verified end-to-end: listener decodes the tank registers; Zeek logs all 6 reads
  (1/s) + 1 write; conn.log shows `service=modbus`.
- **Learned:** installed Zeek 8.2 (brew) and scapy 2.6.1 (py3.14 OK). Two gotchas:
  (1) a synthetic pcap needs a real TCP handshake + growing seq numbers or Zeek
  drops packets as retransmissions; (2) Zeek only treats port 502 as Modbus —
  port 5020 (the laptop test) needs `Analyzer::register_for_port(...)`.
- **Next:** capture the REAL Stage A traffic (`sudo tcpdump -i lo0 'tcp port 5020'`),
  then Month 2 — the bridge (pymodbus client -> MQTT) and the digital twin.

---

## 2026-07-07 — Part 3 (Month 2): digital twin + live pipeline works

- **Did:** Built `bridge/bridge.py` (pymodbus client polling the PLC 1x/s ->
  publishes JSON to MQTT `plant/telemetry`), `twin/twin.py` (MQTT subscriber that
  keeps live state + an expected-value check + writes to InfluxDB), and
  `pipeline/docker-compose.yml` (mosquitto + influxdb 2.7 + grafana 11.1, with
  Grafana pre-provisioned to the InfluxDB datasource). Ran the whole chain live:
  bridge published, twin received, InfluxDB stored 11+ points tracking the tank,
  Grafana up with the datasource healthy. Injected a fake message (pressure 99 vs
  expected 5.0) and the twin correctly flagged ANOMALY -> anomaly seed proven.
- **Learned:** paho-mqtt 2.x needs `mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)`
  and on_connect/on_message got new signatures. InfluxDB 2.7 auto-setup via
  DOCKER_INFLUXDB_INIT_* env (org=honeynet, bucket=plant, dev token). All three
  images are native arm64 (no --platform). Grafana provisioning path
  `/etc/grafana/provisioning`. Docker infra left running.
- **Next:** build the Grafana panels (Flux queries in pipeline/README.md) and
  measure the real PLC->twin delay. Then Month 3 — live decoys fed by the twin.

---

## 2026-07-07 — Part 4 (Month 3 core): live decoy vs static baseline

- **Did:** Built `honeynet/modbus-decoy/decoy.py` — a live Modbus decoy: a
  pymodbus server whose registers are fed from the twin over MQTT, with a custom
  DecoyStore that logs every attacker read/write (feed() stays silent). Built
  `static_decoy.py` (matched frozen baseline) and set up Conpot via
  `honeynet/conpot/docker-compose.yml`. Verified the whole comparison live:
  live decoy MOVES and mirrors the real plant; static decoy + Conpot are FROZEN.
  Proved the one-way mirror (attacker wrote 9999 to the decoy, real PLC
  unaffected) and that reads/writes are logged.
- **Learned:** pymodbus `ModbusSlaveContext` adds +1 to addresses, so initial
  values passed to `ModbusSequentialDataBlock(0, vals)` land off-by-one — write
  with `setValues(3, 0, ...)` instead (matches the PLC). Conpot: amd64 image runs
  under Rosetta; default template puts Modbus on container port 5020 (not 502),
  and its registers use classic addressing (coils@1, input regs@30001) so reads
  at 0 return exceptions — hence the matched static_decoy as the clean control.
- **Next:** Kali attacker on isolated net + the 5 attack scenarios (live vs
  static) + Zeek/ELK logging, then JupyterLab analysis.

---

## 2026-07-07 — Part 5 (Month 3): attacker + logging

- **Did:** Wrote the 5 attack scripts (`attacker/scripts/`): recon (nmap),
  enumeration, unauthorised write, HMI brute-force, replay/robustness, plus
  `run_all.py`. Built a decoy HMI login honeypot (`honeynet/hmi/decoy_hmi.py`)
  that logs every attempt. Ran the whole suite against the live+static decoys:
  Scenario 2 nailed the core result (LIVE=3 distinct readings, STATIC=1 frozen).
  Writes accepted+logged, 16 brute-force attempts logged w/ source IP, decoy
  survived a malformed frame. Wrote `analysis/summarize_attacks.py` (light log
  analysis) and verified it (9 decoy events, 16 HMI attempts). Provided a
  lightweight attacker Dockerfile + the 3-network isolation design, and the ELK
  stack (`logging/`) as an OPTIONAL heavy tier.
- **Learned:** Docker VM is only ~4 GB, so full ELK (ES 1-2 GB) is not safe next
  to the pipeline -> used the light path (JSON logs + summarizer), which the task
  itself allowed as the fallback. nmap `-sV` hangs ~40s on a bare Modbus port;
  use `-sT` + modbus-discover instead. On host test ports nmap can't label it
  'modbus' (only on 502).
- **Next:** Month 4 — measure results (twin fidelity/delay, live-vs-static,
  detection coverage) in JupyterLab, and write the project. Optional: containerise
  everything onto the 3 isolated networks; add S7/OPC-UA decoys.

---

## 2026-07-07 — Part 6 (Month 4): analysis, project, clean repo — CORE COMPLETE

- **Did:** Wrote `analysis/collect_data.py` (records real fidelity + believability
  data from the running lab) and `analysis/analysis.py` (the 3 charts + optional
  KMeans), converted to an executed `analysis/analysis.ipynb`. Measured REAL
  results: twin fidelity mean error **0.11%**; live decoy std **2.6** vs static
  **0.0**; detection coverage **100%** (101 reads, 2 writes, 16 logins captured).
  Wrote the project draft `docs/report.md` (full structure, filled from the build),
  rewrote the top-level README, and added a pinned top-level `requirements.txt`.
- **Learned:** Python 3.14 needs the LATEST matplotlib/pandas/sklearn (old pins had
  no 3.14 wheels) -> matplotlib 3.11, pandas 3.0, sklearn 1.9. jupytext + nbconvert
  turn a `# %%` .py into an executed notebook with embedded charts.
- **Next:** commit everything (a whole project is unversioned). Optional polish:
  containerise onto the 3 networks, S7/OPC-UA decoys + HoneyPLC, run full ELK on a
  bigger machine, grow attack dataset for ML. Then finish writing the project prose.

---

## 2026-07-07 — Honeynet Operations Console (live dashboard)

- **Did:** Built `honeynet/monitor/` — a Flask dashboard (console.py + index.html)
  that reads the 3 decoys over Modbus and tails the honeypot JSON logs, showing
  plant telemetry + live-vs-static decoys + a live attack feed in one dark SOC
  screen. It is the lightweight stand-in for the (too-heavy) Kibana. Verified live
  in Chrome via a screenshot: live decoy 75.5% MOVING mirrors the real PLC, static
  50.0% FROZEN, 99 attacker events + 16 logins in the feed. Colours validated with
  a colourblind-safe palette (real=blue #3987e5, live=aqua #199e70, static=yellow
  #c98500; status green/amber/red).
- **Learned:** opened the console in Chrome to view it live
  (`open -a "Google Chrome" http://localhost:8099`). Runs on port 8099.
- **Fixed a self-inflicted bug:** the console first polled the live decoy over
  Modbus every 2s, and the decoy logged each poll as an "attacker read" -> the
  feed flooded with hundreds of identical reads. Fix: the console now takes the
  live decoy's value from the `plant/telemetry` MQTT feed (what the decoy is fed)
  and never sends Modbus to the decoy, so monitoring no longer pollutes the log.

---

## 2026-07-07 — Honeypot FLEET + threat-intel dashboard + dataset replayer

- **Did:** Built `honeynet/fleet/` — a real honeynet. `devices.py` = 8 fake
  devices (tank, boiler, pump station, chlorine, power meter, HVAC, conveyor,
  genset), each a self-simulating Modbus decoy on 127.0.0.1 behind a **sensor**
  (async relay) on a public port that logs the attacker's **source IP**.
  `run_fleet.py` starts them all (ports 5101-5108). Built `dashboard.py` +
  `dashboard.html` = threat-intelligence dashboard (attacker IPs, honeypots hit,
  tamper writes, live feed) on :8100 — verified in Chrome. Built `replay_csv.py`
  (drive a honeypot from a real dataset CSV) + verified with sample_dataset.csv.
- **Learned:** pymodbus doesn't expose the client IP for TCP (`request_tracer`
  only gets addr for UDP), so a front sensor/relay is the clean way to capture
  source IPs (also protocol-agnostic). Dashboard JS bug: element ids used hyphens
  (`k-hp`) but JS referenced them as bare globals (`k_hp`) -> crash; fixed to
  getElementById. Backends run via `StartAsyncTcpServer` as asyncio tasks +
  sensors via `asyncio.start_server` in one loop; sims in daemon threads.
- **Next:** mixed protocols — add an S7 decoy (`python-snap7`, `brew install
  snap7`) and an OPC UA decoy (`asyncua`) behind their own sensors; wire the fleet
  onto the isolated Docker networks; download a real dataset (HAI/SWaT) for the
  analysis chapter.

---

## 2026-07-07 — Attacker geolocation on the threat dashboard

- **Did:** Added `honeynet/fleet/geo.py` (offline IP->country via `geoip2fast` —
  no key, no internet, localhost/private -> "Local"). Enriched the dashboard:
  attacker table now has a **Location** column (flag + country), plus a
  Countries KPI and a "Top attacker locations" panel with proportional bars.
  `demo_attackers.py` seeds example global IPs so the country view shows data
  (lab traffic is all localhost). Verified in Chrome: US/FR/BR/AU/JP/CN/RU/DE/NL
  flags, real 127.0.0.1 shown as Localhost alongside.
- **Learned:** `geoip2fast` bundles its DB and works on py3.14. Two restart
  gotchas: `pkill -f "fleet/dashboard.py"` didn't match (cmdline is just
  `dashboard.py`), and the stale process kept :8100 so the new geo code never
  bound -> always `pkill -f dashboard.py` and confirm the port is free.
- **Next:** real-time push (Server-Sent Events) instead of 2s polling, if wanted;
  a world map; wire fleet onto isolated Docker nets.

---

## 2026-07-07 — Real-time PUSH: dashboard now streams via SSE

- **Did:** Replaced the threat dashboard's 2s polling with **Server-Sent Events**.
  `dashboard.py` gained `/api/stream` (a generator that yields `data: <state>` only
  when `build()` changes, keep-alive otherwise; `app.run(threaded=True)`).
  `dashboard.html` uses `EventSource("/api/stream")` + a `render(d)` function
  (initial fetch for first paint, then live pushes). Verified: captured the stream
  for 8s while firing an attack at t=3s -> exactly 2 data frames pushed, counts
  jumped 60->61 connections / 3->4 writes the moment the attack landed.
- **Learned:** SSE is the simplest true-push for a dashboard; the server must be
  threaded so the open stream doesn't block other routes. This complements the
  project's existing MQTT pub/sub, which is the real-time *broadcast* backbone for
  the telemetry (bridge publishes -> twin/decoys/console subscribe).
- **Next (optional):** MQTT-over-WebSocket so the browser subscribes straight to
  Mosquitto; a world map; S7/OPC UA decoys; wire fleet onto the isolated nets.

---

## 2026-07-07 — Believability measurement: does the fake factory look real?

- **Did:** Built two evaluation tools. `analysis/believability_test.py` fingerprints
  a device (values-change, device-identity, plausible values, bad-request handling,
  timing) and scores it: LIVE decoy 4/5 vs STATIC 3/5. `analysis/profile_and_compare.py`
  + `real_plc_reference.json` compare a decoy to a REAL Schneider Modicon M340
  profile: the live decoy matches **8/9 traits (89%)** — supports the full Modbus
  function set, rejects bad addresses, live values. **The one gap: device identity**
  (a bare pymodbus server doesn't answer Read Device Identification with a
  vendor/product; a real PLC does).
- **Learned:** this is the honest "profile the real, then mirror it" evidence for
  the project. Closing the single gap = attach a `ModbusDeviceIdentification`
  (vendor/product/version) to the server via the `identity=` arg -> would make it
  9/9. Custom decoys are strong on live values, weak on banners; Conpot is the
  reverse; the ideal decoy has both.
- **Next:** mirror the gap — give each fleet device a realistic vendor identity
  (Schneider/Siemens/...) so it profiles 9/9; optionally run OpenPLC as a LIVE real
  reference instead of the spec-based one.

---

## 2026-07-07 — Threat dashboard redesign (looks like a real SOC product)

- **Did:** User said the old dashboard "looks made by AI". Rebuilt
  `honeynet/fleet/dashboard.html` to a refined SIEM aesthetic (reference: a real
  security-alerts console): slate-navy palette, shield logo, search bar, a
  **Saved Views** sidebar (All / Critical / Enumerating / Foreign / Local, with
  counts + client-side filtering), a **Threat Overview** with severity bars, a
  Fleet Status card, and an alerts-style table (checkbox, severity pill, shield +
  IP + "N connections · N targets", target honeypot, relative "13h ago" time,
  Active/Contained status, country-flag avatar). Backend unchanged; still SSE-fed.
  Verified in Chrome — clean, professional, filters work.
- **Learned:** the "AI look" was pure black + generic tiles; the fix is a chosen
  slate palette, real hierarchy/spacing, soft status pills (tinted bg + colored
  text), and a product layout (sidebar + toolbar + table) rather than a wall of
  cards. `open -a Chrome URL` refocuses an existing tab (keeps its JS filter
  state) rather than always reloading fresh.
- **Restored (same day):** the redesign had dropped 3 views the old dashboard had
  — the per-device fleet grid, the top-locations ranking, and the live connection
  feed. Backend data was never lost (still returned fleet/feed/top_locations); re-
  added all three to `dashboard.html` in the refined style (Top locations in the
  sidebar; Monitored-devices grid + Live connection feed in a bottom row).
- **Added:** liveness-probe detection. The sensor now counts attacker->backend
  bytes; a connection that sends 0 bytes (TCP connect / port scan = "is it alive?")
  is logged as a `probe` event (with IP + honeypot) instead of looking like a real
  session. Dashboard shows "Liveness probes" in Fleet Status + a per-device probe
  count. Verified: 4 connect-only checks -> 4 probe events; a real Modbus read was
  NOT flagged. (ICMP ping is network-layer -> caught by Zeek, not the app.)
- **Adversarial hardening (same day):** built `analysis/honeypot_detector.py`
  (plays the attacker: fn-43 identity check, value-realism, clone check, service
  surface) — found 3 tells on the fleet: no device identity, all devices identical
  (clones), only-Modbus. Fixed the top two by giving each device a distinct REAL
  vendor identity (Schneider/WAGO/Siemens/Rockwell/Honeywell/DSE) in devices.py,
  reported over Modbus fn 43.
- **Real bug found + fixed:** pymodbus `ModbusDeviceIdentification` stores its data
  in a CLASS-level dict = a per-process singleton, so all 8 servers in one process
  reported the LAST identity set. Fix: run each device backend in its OWN process
  (`multiprocessing.Process`), sensors stay in the main asyncio process relaying to
  them. Separate processes = separate class state = distinct identities — and it
  matches real deployment (each device = separate hardware/container). Verified:
  8 distinct identities; believability 4/5->5/5; real-PLC match 8/9->9/9; detector
  3->1 tells; reads/writes still logged across processes; dashboard fine.
- **Remaining tell (honest):** "only Modbus exposed" (no web UI/SNMP per device),
  plus network-level tells (OS fingerprint via nmap -O, MAC vendor) that need
  container/VM-level fixes.
- **Next:** close the last tell (fake web UI/SNMP per device, or Conpot); S7/OPC UA
  decoys; unify onto the 3 isolated nets.

---

## 2026-07-10 — Resilience / self-pentest: "how hard to crack?"

- **Did:** Built `analysis/resilience_test.py` — reframes "how easy to attack" for a
  honeypot: it's meant to be EASY to interact with (the lure) but HARD to crash or
  escape. Runs the crack attacks: 150 malformed/garbage frames, 60 concurrent
  connections, 100 rapid unauthorised writes. Verified vs fleet device 5101:
  survived all three, stayed up, still accepts new clients; writes accepted by
  design; containment holds (a decoy write can't reach the real plant).
- **Learned:** the flood test must be fire-and-forget (don't `recv` per frame, or
  150 x 2s timeout = 5 min hang). Now the project has a 3-tool self-evaluation
  suite: believability_test (looks real?), honeypot_detector (detectable as fake?),
  resilience_test (crackable/crashable?).
- **Next:** same as above; git already pushed to GitHub (AyushSagar299/ics-honeynet).

---

## 2026-07-10 — Real ICS traffic: the 4SICS capture (tutor-shared references)

- **Did:** Tutor shared 4 links (Grid-Watch, NETRESEC PCAP4SICS, GhostPLC, Gridwolf) —
  3 already in the roadmap; the new one is real ICS pcaps. Downloaded the smallest
  4SICS capture (25 MB real conference-lab ICS traffic) to
  `listener/scapy/4sics-geeklounge.pcap` and ran Zeek on it (logs in
  `listener/zeek/logs-4sics/`). Finding: **real Siemens S7** traffic — a real S7 PLC
  at 10.10.10.10 hit **7,199 times** by one attacker (10.10.10.30), ~95% probing
  (RSTO) + ~5% real sessions (S1). This REAL attacker pattern validates the design:
  the sensor captures exactly this connection flood, and the resilience test proved
  the honeypot survives it.
- **Learned:** this smallest file is S7-dominated (Modbus/DNP3 are in the bigger
  134/200 MB files). Zeek has built-in Modbus + DNP3 analyzers but NOT S7comm (needs
  the ICSNPP-s7comm plugin, or use Wireshark's native s7comm dissector). The Scapy
  `dpi_listener.py` is Modbus-only, so it finds nothing in this S7 file.
- **Next:** optionally grab a bigger 4SICS file for real Modbus to run the Scapy
  listener on; add S7 decoding (Zeek plugin) as future work; cite this real capture
  in the Month 1 / evaluation chapters.
- **Next:** same as above — commit everything; optional polish.
