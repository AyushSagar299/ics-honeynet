"""
console.py -- the Honeynet Operations Console.

A small live dashboard that shows, in one screen:
  * the plant telemetry (level, temperature, pressure, anomaly),
  * the live decoy vs the static decoy (moving vs frozen),
  * a live feed of what attackers are doing to the honeynet.

It is the lightweight stand-in for Kibana: instead of the heavy ELK stack (too
big for a 4 GB Mac), it reads the plant/static-decoy over Modbus and tails the
honeypot JSON logs. Open http://localhost:8099 .

Important: the console does NOT poll the *live decoy* over Modbus. If it did,
every 2-second refresh would be logged by the decoy as an attacker read and
flood the honeypot log. Instead it takes the live decoy's value from the same
MQTT feed the decoy is fed from, so monitoring never pollutes the attack log.
"""

import os
import json
import threading

from flask import Flask, jsonify, send_from_directory
from pymodbus.client import ModbusTcpClient
import paho.mqtt.client as mqtt

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

DECOY_LOG = os.environ.get("DECOY_LOG", os.path.join(ROOT, "analysis", "decoy.log"))
HMI_LOG = os.environ.get("HMI_LOG", os.path.join(ROOT, "analysis", "hmi.log"))

MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))

# the two Modbus devices we read directly (neither logs reads):
#   the real PLC (ground truth) and the static decoy (a plain server)
real_client = ModbusTcpClient("127.0.0.1", port=int(os.environ.get("REAL_PORT", "5020")))
static_client = ModbusTcpClient("127.0.0.1", port=int(os.environ.get("STATIC_PORT", "5022")))

# the live decoy's value comes from MQTT (what the decoy is fed), not Modbus
live_state = {}

app = Flask(__name__)


def read_device(client):
    """Read the 6 tank registers, or return None if the device is down."""
    try:
        if not client.connect():
            return None
        r = client.read_holding_registers(0, count=6)
        if r.isError():
            return None
        reg = r.registers
        return {"level": reg[0] / 10, "temp": reg[1] / 10, "pressure": reg[2] / 10,
                "pump": reg[3], "heater": reg[4], "valve": reg[5]}
    except Exception:
        return None


def start_mqtt():
    """Follow the same telemetry the live decoy is fed, in the background."""
    def on_connect(c, u, flags, reason, props):
        c.subscribe("plant/telemetry")

    def on_message(c, u, msg):
        try:
            live_state.update(json.loads(msg.payload))
        except ValueError:
            pass

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(MQTT_HOST, MQTT_PORT, 60)
        client.loop_forever()
    except OSError:
        pass


threading.Thread(target=start_mqtt, daemon=True).start()


def load_json_lines(path):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    return rows


def build_attacks():
    """Turn the honeypot logs into counts + a newest-first feed."""
    decoy = load_json_lines(DECOY_LOG)
    hmi = load_json_lines(HMI_LOG)

    feed = []
    for e in decoy:
        if e.get("event") == "write":
            feed.append({"ts": e.get("ts"), "source": "modbus client", "action": "WRITE",
                         "detail": f"reg {e.get('address')} = {e.get('values')}", "severity": "critical"})
        else:
            feed.append({"ts": e.get("ts"), "source": "modbus client", "action": "READ",
                         "detail": f"regs from {e.get('address')} x{e.get('count')}", "severity": "info"})
    for e in hmi:
        feed.append({"ts": e.get("ts"), "source": e.get("ip", "?"), "action": "LOGIN",
                     "detail": f"{e.get('username')} : {e.get('password')}", "severity": "warning"})

    feed.sort(key=lambda x: x["ts"] or "", reverse=True)
    counts = {
        "read": sum(1 for e in decoy if e.get("event") == "read"),
        "write": sum(1 for e in decoy if e.get("event") == "write"),
        "login": len(hmi),
    }
    return {"counts": counts, "feed": feed[:25]}


@app.route("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.route("/api/state")
def state():
    real = read_device(real_client)
    static = read_device(static_client)

    # the live decoy shows whatever the twin last published
    live = None
    if live_state:
        live = {"level": live_state.get("level"), "temp": live_state.get("temp"),
                "pressure": live_state.get("pressure"), "pump": live_state.get("pump")}

    # telemetry + a simple anomaly check, from the real PLC (ground truth)
    telemetry = None
    if real:
        expected = round(real["level"] * 0.1, 1)
        telemetry = {"level": real["level"], "temp": real["temp"], "pressure": real["pressure"],
                     "expected_pressure": expected, "pump": real["pump"],
                     "anomaly": abs(real["pressure"] - expected) > 0.5}

    return jsonify({"real": real, "live": live, "static": static,
                    "telemetry": telemetry, "attacks": build_attacks()})


if __name__ == "__main__":
    print("Honeynet Operations Console on http://localhost:8099", flush=True)
    app.run(host="0.0.0.0", port=int(os.environ.get("CONSOLE_PORT", "8099")))
