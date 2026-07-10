"""
twin.py -- the digital twin.

It listens to the 'plant/telemetry' topic, keeps the latest known state of the
plant (this dictionary IS the twin), works out what some values *should* be, and
stores everything in InfluxDB so Grafana can draw it.

The expected-value check is the first small step towards anomaly detection:
later, if an attacker writes a fake value into a decoy, the "expected vs actual"
gap is how we notice.
"""

import os
import json

import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC = "plant/telemetry"

INFLUX_URL = os.environ.get("INFLUX_URL", "http://127.0.0.1:8086")
INFLUX_TOKEN = os.environ.get("INFLUX_TOKEN", "dev-token-please-change")
INFLUX_ORG = os.environ.get("INFLUX_ORG", "honeynet")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "plant")

# the twin's memory: the latest state of the plant
twin_state = {}

influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx.write_api(write_options=SYNCHRONOUS)


def expected_pressure(level):
    """In our tank the pressure should be about level x 0.1."""
    return round(level * 0.1, 1)


def on_connect(client, userdata, flags, reason_code, properties):
    print("twin connected to MQTT, waiting for telemetry...", flush=True)
    client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    state = json.loads(msg.payload)
    twin_state.update(state)                 # the twin now knows the newest values

    want = expected_pressure(state["level"])
    drift = abs(state["pressure"] - want)
    anomaly = drift > 0.5                     # more than 0.5 bar off = suspicious

    tag = "ANOMALY" if anomaly else "ok"
    print(f"twin: level={state['level']}%  temp={state['temp']}C  "
          f"pressure={state['pressure']} (expected {want})  {tag}", flush=True)

    # save it so Grafana can chart it
    point = (Point("tank")
             .field("level", float(state["level"]))
             .field("temp", float(state["temp"]))
             .field("pressure", float(state["pressure"]))
             .field("expected_pressure", float(want))
             .field("pump", int(state["pump"]))
             .field("anomaly", 1 if anomaly else 0))
    try:
        write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print("could not write to InfluxDB:", e, flush=True)


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message
client.connect(MQTT_HOST, MQTT_PORT, 60)
client.loop_forever()
