"""
decoy.py -- a LIVE Modbus decoy for the honeynet.

It looks exactly like the real tank PLC: same registers, same protocol, same
port. But its values are not from a real process -- they are copied from the
digital twin over MQTT. So an attacker who reads this decoy sees the real
plant's live, moving values and cannot easily tell it is a trap. That is the
heart of the thesis.

Safety -- this is a ONE-WAY mirror:
  * values flow twin -> decoy only.
  * if an attacker writes to the decoy, it is logged and stays here. It can
    never reach the real PLC, because the decoy is a completely separate
    program on a separate network.
"""

import os
import json
import time
import threading
from datetime import datetime

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.server import StartTcpServer
import paho.mqtt.client as mqtt

MODBUS_PORT = int(os.environ.get("MODBUS_PORT", "5021"))   # 502 in Docker
MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC = "plant/telemetry"
LOG_FILE = os.environ.get("DECOY_LOG", "decoy.log")


def log_attacker(kind, detail):
    """Write one JSON line about what a client did (a client here = an attacker,
    because only attackers talk to a honeypot)."""
    line = {"ts": datetime.now().isoformat(timespec="seconds"), "event": kind}
    line.update(detail)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(line) + "\n")
    print("attacker:", kind, detail, flush=True)


class DecoyStore(ModbusSlaveContext):
    """A normal Modbus store, but it logs every read and write from a client.
    Our own feeder updates the registers through feed(), which does NOT log."""

    def getValues(self, fc_as_hex, address, count=1):
        log_attacker("read", {"fc": fc_as_hex, "address": address, "count": count})
        return super().getValues(fc_as_hex, address, count)

    def setValues(self, fc_as_hex, address, values):
        log_attacker("write", {"fc": fc_as_hex, "address": address, "values": list(values)})
        return super().setValues(fc_as_hex, address, values)

    def feed(self, values):
        # our feeder copies the twin's values in quietly (not an attacker action)
        super().setValues(3, 0, values)


store = DecoyStore(hr=ModbusSequentialDataBlock(0, [0] * 100))
context = ModbusServerContext(slaves=store, single=True)


def state_to_registers(state):
    """Same register map as the real PLC, so the decoy looks identical."""
    return [
        int(state["level"] * 10),
        int(state["temp"] * 10),
        int(state["pressure"] * 10),
        int(state["pump"]),
        int(state["heater"]),
        int(state["valve"]),
    ]


def on_connect(client, userdata, flags, reason_code, properties):
    client.subscribe(TOPIC)
    print("decoy connected to the twin feed", flush=True)


def on_message(client, userdata, msg):
    state = json.loads(msg.payload)
    store.feed(state_to_registers(state))       # copy the live values into the decoy


def run_feeder():
    """Background thread: keep the decoy's registers in sync with the twin."""
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    for _ in range(15):
        try:
            client.connect(MQTT_HOST, MQTT_PORT, 60)
            break
        except OSError:
            print("decoy waiting for the MQTT broker...", flush=True)
            time.sleep(1)
    client.loop_forever()


if __name__ == "__main__":
    threading.Thread(target=run_feeder, daemon=True).start()
    print(f"LIVE Modbus decoy on port {MODBUS_PORT}, fed by the twin. Ctrl+C to stop.", flush=True)
    StartTcpServer(context=context, address=("0.0.0.0", MODBUS_PORT))
