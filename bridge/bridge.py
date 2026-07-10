"""
bridge.py -- read the PLC and publish its values to MQTT.

It connects to the tank PLC over Modbus, reads the 6 registers once a second,
turns them into a small JSON message, and publishes it to the topic
'plant/telemetry'. Everything else in the pipeline (the twin, the database,
the dashboard, the decoys) just listens to that one topic.

This is the "channel real-time telemetry into the digital twin" task.
"""

import os
import json
import time

from pymodbus.client import ModbusTcpClient
import paho.mqtt.client as mqtt

# where to read from and where to publish (Docker can override with env vars)
MODBUS_HOST = os.environ.get("MODBUS_HOST", "127.0.0.1")
MODBUS_PORT = int(os.environ.get("MODBUS_PORT", "5020"))
MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC = "plant/telemetry"


def registers_to_state(regs):
    """Turn the 6 raw registers into named, real-world values.
    Same register map as tank_plc.py (the first three were stored x10)."""
    return {
        "level": regs[0] / 10,
        "temp": regs[1] / 10,
        "pressure": regs[2] / 10,
        "pump": regs[3],
        "heater": regs[4],
        "valve": regs[5],
    }


plc = ModbusTcpClient(MODBUS_HOST, port=MODBUS_PORT)
broker = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

# connect to the broker, retrying in case it is still starting up
for _ in range(15):
    try:
        broker.connect(MQTT_HOST, MQTT_PORT, 60)
        break
    except OSError:
        print("waiting for the MQTT broker...", flush=True)
        time.sleep(1)
broker.loop_start()

print(f"bridge: Modbus {MODBUS_HOST}:{MODBUS_PORT}  ->  MQTT {MQTT_HOST}:{MQTT_PORT}/{TOPIC}", flush=True)

while True:
    if not plc.connect():
        print("cannot reach the PLC, retrying...", flush=True)
        time.sleep(1)
        continue

    result = plc.read_holding_registers(0, count=6)
    if result.isError():
        print("modbus read error:", result, flush=True)
        time.sleep(1)
        continue

    state = registers_to_state(result.registers)
    state["ts"] = time.time()
    broker.publish(TOPIC, json.dumps(state))
    print("published:", state, flush=True)
    time.sleep(1)
