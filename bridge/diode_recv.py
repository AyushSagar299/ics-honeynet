"""
diode_recv.py -- the honeynet-facing half of the software data diode.

this is the RECEIVE side. it binds a UDP socket, waits for the datagrams
that diode_send.py pushes across, and forwards each one into MQTT on
plant/telemetry so the shadow, the database and the decoys keep getting
fed exactly the same messages as before.

two things make the reverse direction impossible in this code:
 - i read with sock.recv(), not recvfrom(), so the sender's address never
   even reaches application code. there is literally nothing to reply to.
 - this module never sends anything toward the plant side. its only output
   is the MQTT publish, which points further into the honeynet direction.

udp is fire and forget, so a datagram can get lost and the receiver cannot
ask for a resend (a real hardware diode has the same property, no acks).
the seq field from the sender lets me at least log when a frame was
dropped. for once-a-second telemetry on localhost this is fine.
"""

import os
import json
import time
import socket

DIODE_HOST = os.environ.get("DIODE_HOST", "127.0.0.1")
DIODE_PORT = int(os.environ.get("DIODE_PORT", "5701"))

MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC = "plant/telemetry"


class DiodeReceiver:
    """receive-only end of the diode. binds the UDP port and hands out the
    decoded state dicts one by one."""

    def __init__(self, host=DIODE_HOST, port=DIODE_PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.last_seq = None

    def recv_state(self, timeout=None):
        """block until one datagram arrives, return it as a dict.
        plain recv on purpose: no peer address, nothing to answer."""
        self.sock.settimeout(timeout)
        data = self.sock.recv(65535)
        state = json.loads(data.decode())
        seq = state.pop("seq", None)
        if self.last_seq is not None and seq is not None and seq != self.last_seq + 1:
            print(f"diode recv: seq jumped {self.last_seq} -> {seq}, udp dropped something", flush=True)
        self.last_seq = seq
        return state

    def close(self):
        self.sock.close()


def run_receiver():
    """the receive side main loop: recv from the diode, publish to MQTT."""
    import paho.mqtt.client as mqtt

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

    rx = DiodeReceiver()
    print(f"diode recv side: UDP {DIODE_HOST}:{DIODE_PORT}  ->  MQTT {MQTT_HOST}:{MQTT_PORT}/{TOPIC}", flush=True)

    while True:
        try:
            state = rx.recv_state()
        except (json.JSONDecodeError, UnicodeDecodeError):
            # a malformed datagram gets dropped, not answered
            print("diode recv: dropped a malformed datagram", flush=True)
            continue
        broker.publish(TOPIC, json.dumps(state))
        print("published:", state, flush=True)


if __name__ == "__main__":
    run_receiver()
