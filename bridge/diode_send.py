"""
diode_send.py -- the plant-facing half of the software data diode.

this is the SEND side. it reads the tank PLC over Modbus once a second and
pushes each reading out as a single UDP datagram to the receive side
(diode_recv.py). that is all it does.

the one-way property is structural, not a firewall rule: this module never
opens a listening socket and never calls recv anywhere. there is simply no
code path that could accept data coming back from the honeynet side. the
self test (diode_selftest.py) actually scans this file's source and fails
if a recv, bind, listen or accept call ever sneaks in.

honest note: this is a SOFTWARE simulation of a data diode. it enforces the
one-way flow at the transport/application layer. a real data diode is a
hardware optical device that enforces it at layer 1, where the fibre
physically has no return path. i am not claiming this code is that. it
complements analysis/zero_egress_test.py (which checks app-level
containment) by making the one-way flow structural inside the bridge.

small caveat i want to be upfront about: a UDP socket still gets a local
ephemeral port from the kernel, and the kernel would queue datagrams sent
at it. but since this code never reads from the socket, those bytes can
never reach application code, so they can never influence the plant side.
"""

import os
import json
import time
import socket

# where the receive side of the diode lives (localhost only, rule 5)
DIODE_HOST = os.environ.get("DIODE_HOST", "127.0.0.1")
DIODE_PORT = int(os.environ.get("DIODE_PORT", "5701"))

# where the real PLC is (same defaults as the old bridge)
MODBUS_HOST = os.environ.get("MODBUS_HOST", "127.0.0.1")
MODBUS_PORT = int(os.environ.get("MODBUS_PORT", "5020"))


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


class DiodeSender:
    """send-only end of the diode. wraps a UDP socket and only ever calls
    sendto on it. fire and forget, no acks, nothing comes back."""

    def __init__(self, host=DIODE_HOST, port=DIODE_PORT):
        self.dest = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.seq = 0

    def push(self, state):
        # tag with a sequence number so the receiver can at least notice
        # if udp dropped a frame (it cannot ask for a resend, on purpose)
        msg = dict(state)
        msg["seq"] = self.seq
        self.seq += 1
        self.sock.sendto(json.dumps(msg).encode(), self.dest)

    def close(self):
        self.sock.close()


def make_modbus_reader(host=MODBUS_HOST, port=MODBUS_PORT):
    """returns a function that reads the PLC once and gives back a state
    dict, or None if the plant is not reachable right now."""
    from pymodbus.client import ModbusTcpClient

    plc = ModbusTcpClient(host, port=port)

    def read_once():
        if not plc.connect():
            return None
        result = plc.read_holding_registers(0, count=6)
        if result.isError():
            return None
        return registers_to_state(result.registers)

    return read_once


def run_sender(read_once, sender=None, period=1.0):
    """the send side main loop: read the plant, push through the diode.
    read_once is injectable so the self test can use a stub plant."""
    if sender is None:
        sender = DiodeSender()
    while True:
        state = read_once()
        if state is None:
            print("diode send: cannot read the PLC, retrying...", flush=True)
        else:
            state["ts"] = time.time()
            sender.push(state)
            print("diode send:", state, flush=True)
        time.sleep(period)


if __name__ == "__main__":
    print(f"diode send side: Modbus {MODBUS_HOST}:{MODBUS_PORT}  ->  UDP {DIODE_HOST}:{DIODE_PORT}", flush=True)
    run_sender(make_modbus_reader())
