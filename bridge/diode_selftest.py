"""
diode_selftest.py -- show the diode works forward and cannot work backward.

run it with:  .venv/bin/python bridge/diode_selftest.py

no real PLC or MQTT broker is needed: the plant read is a stub here, on
purpose, so what gets tested is the diode mechanism itself. it does four
checks:

 1. forward: stub plant readings go through DiodeSender and come out of a
    DiodeReceiver on localhost, in order, with sequence numbers.
 2. reverse over TCP: try to open a TCP connection to the diode port from
    the honeynet side. neither half of the diode listens on TCP, so the
    connect must be refused. there is no session to talk back over.
 3. reverse over UDP: fire a datagram at the send side's own socket. the
    kernel will queue it, but the send side never reads its socket, so the
    bytes can never reach application code (check 4 proves "never").
 4. structural: scan the source of diode_send.py and fail if it contains
    a recv, recvfrom, bind, listen or accept call anywhere. the one-way
    property is a property of the code, not a firewall rule someone could
    switch off.

honest note, same as in the other diode files: this simulates a data diode
in software at the transport/application layer. a real diode is a layer 1
hardware device. i am demonstrating the software construction, not
claiming hardware guarantees.
"""

import os
import time
import socket

from diode_send import DiodeSender
from diode_recv import DiodeReceiver

HERE = os.path.dirname(os.path.abspath(__file__))

# use a different port than the live diode so this test never collides
# with a running bridge
TEST_PORT = 5702


def check_forward():
    print("[1] forward path: plant side -> diode -> honeynet side")
    rx = DiodeReceiver("127.0.0.1", TEST_PORT)
    tx = DiodeSender("127.0.0.1", TEST_PORT)

    # stub plant readings, roughly what tank_plc.py would give
    fakes = [
        {"level": 52.1, "temp": 41.3, "pressure": 2.4, "pump": 1, "heater": 0, "valve": 1},
        {"level": 52.4, "temp": 41.2, "pressure": 2.4, "pump": 1, "heater": 0, "valve": 1},
        {"level": 52.7, "temp": 41.2, "pressure": 2.5, "pump": 1, "heater": 0, "valve": 1},
    ]
    for f in fakes:
        f["ts"] = time.time()
        tx.push(f)

    for i in range(len(fakes)):
        try:
            got = rx.recv_state(timeout=2)
        except socket.timeout:
            # udp gives no delivery promise; report it instead of crashing the test
            print(f"    FAIL: frame {i} never arrived within 2 s")
            raise SystemExit(1)
        print(f"    received frame {i}: level={got['level']} temp={got['temp']} pump={got['pump']}")

    print("    ok, telemetry flows plant -> honeynet")
    return tx, rx


def check_reverse_tcp():
    print("[2] reverse path over TCP: honeynet side tries to connect back")
    try:
        socket.create_connection(("127.0.0.1", TEST_PORT), timeout=2)
    except ConnectionRefusedError:
        print("    connection refused: nothing on the diode listens on TCP, no session to talk back over")
        return True
    except OSError as e:
        print(f"    connect failed ({e}): no TCP listener on the diode")
        return True
    print("    PROBLEM: something accepted a TCP connection, the diode is not one-way!")
    return False


def check_reverse_udp(tx):
    print("[3] reverse path over UDP: honeynet side fires a datagram at the send side")
    # the sender never binds, but the kernel gave its socket an ephemeral
    # port on the first sendto. an attacker on the honeynet side who
    # somehow learned that port could aim a datagram at it, so simulate
    # exactly that
    victim = ("127.0.0.1", tx.sock.getsockname()[1])
    attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    attacker.sendto(b'{"valve": 0, "pump": 0}', victim)
    attacker.close()
    print(f"    sent a fake command to the sender's socket {victim}")
    print("    the kernel queues it, but the send side code never reads its socket,")
    print("    so those bytes can never reach the plant side (see check 4)")


def check_structural():
    print("[4] structural check: scan diode_send.py for any receiving call")
    path = os.path.join(HERE, "diode_send.py")
    with open(path) as f:
        src = f.read()

    # these are the only ways python socket code can take data in.
    # searching for the call form with the dot and paren so the words in
    # comments and docstrings do not count.
    forbidden = [".recv(", ".recvfrom(", ".recvmsg(", ".bind(", ".listen(", ".accept("]
    bad = [t for t in forbidden if t in src]
    if bad:
        print(f"    PROBLEM: found {bad} in diode_send.py, the send side can receive!")
        return False
    print(f"    none of {forbidden} appear in diode_send.py")
    print("    the send side has no code path that can take data in. one-way by construction.")
    return True


if __name__ == "__main__":
    print("software data diode self test (simulated diode, app/transport layer)")
    print()
    tx, rx = check_forward()
    print()
    ok_tcp = check_reverse_tcp()
    print()
    check_reverse_udp(tx)
    print()
    ok_src = check_structural()
    tx.close()
    rx.close()
    print()
    if ok_tcp and ok_src:
        print("result: forward path works, reverse path impossible by construction. PASS")
    else:
        print("result: FAIL, see the PROBLEM lines above")
        raise SystemExit(1)
