# The live pipeline + Digital Twin (Month 2)

This is the "real-time telemetry into the digital twin" part. Data flows:

```
tank_plc.py  --Modbus-->  bridge.py  --MQTT-->  Mosquitto  -->  twin.py  -->  InfluxDB  -->  Grafana
 (the PLC)                (publisher)           (broker)       (the twin)     (storage)     (dashboard)
```

- **bridge.py** reads the PLC every second and publishes JSON to `plant/telemetry`.
- **twin.py** listens, keeps the latest state, checks each value against what it
  *should* be (the anomaly seed), and stores it in InfluxDB.
- **Mosquitto / InfluxDB / Grafana** run here in Docker.

## 1. Start the infrastructure
```bash
cd pipeline
docker compose up -d          # mosquitto + influxdb + grafana
```
- InfluxDB: http://localhost:8086  (user `admin`, pass `admin12345`)
- Grafana:  http://localhost:3000  (already connected to InfluxDB)

## 2. Start the live data (three terminals)
```bash
# terminal 1 — the PLC (from real-lab/process-simulator)
../.venv/bin/python ../real-lab/process-simulator/tank_plc.py

# terminal 2 — the bridge
../.venv/bin/python ../bridge/bridge.py

# terminal 3 — the twin
../.venv/bin/python ../twin/twin.py
```
The twin prints a line per reading, e.g.:
```
twin: level=44.0%  temp=26.7C  pressure=4.4 (expected 4.4)  ok
```

## 3. Build the dashboard in Grafana
Open http://localhost:3000 → *Dashboards* → *New* → *Add visualization* →
pick the **InfluxDB** data source, and paste one of these Flux queries per panel:

**Level right now (a Gauge panel):**
```flux
from(bucket: "plant")
  |> range(start: -5m)
  |> filter(fn: (r) => r._measurement == "tank" and r._field == "level")
  |> last()
```

**Level and temperature over time (a Time series panel):**
```flux
from(bucket: "plant")
  |> range(start: -15m)
  |> filter(fn: (r) => r._measurement == "tank" and (r._field == "level" or r._field == "temp"))
```

**Actual vs expected pressure — the anomaly view (a Time series panel):**
```flux
from(bucket: "plant")
  |> range(start: -15m)
  |> filter(fn: (r) => r._measurement == "tank" and (r._field == "pressure" or r._field == "expected_pressure"))
```

Set the dashboard to auto-refresh (top right, e.g. every 5s) and watch it track
the PLC live, about one second behind. **That one-second delay is a thesis result
— measure it.**

## Stop
```bash
docker compose down           # stop the infra (add -v to also wipe stored data)
```
