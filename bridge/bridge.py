"""
bridge.py -- plant -> shadow bridge, now built as a software data diode.

before, this file read the PLC and published to MQTT directly in one loop.
the data flow is still exactly the same (PLC registers -> JSON on the
'plant/telemetry' topic, everything downstream just listens there), but
the bridge is now split into two halves that only talk over a strictly
one-way UDP push:

  diode_send.py  reads the plant, sendto() datagrams      (send only)
  diode_recv.py  recv() datagrams, publishes to MQTT      (receive only)

this file just starts both halves: the receive side as a child process and
the send side in this process. the only channel between them is the UDP
datagrams, and the send side has no recv call and no listening socket, so
there is no code path by which anything on the honeynet side could push
data back toward the plant. reverse flow is impossible by construction,
not just blocked by a rule somewhere.

honest note: this is a SOFTWARE simulation of a data diode. it enforces
the one-way invariant at the transport/application layer. a real data
diode is a hardware optical device that enforces it at layer 1. this code
does not claim to be that. it complements analysis/zero_egress_test.py
(app-level containment) by making the one-way flow structural here in the
bridge. run bridge/diode_selftest.py to see the forward path working and
the reverse path failing.
"""

import os
import sys
import signal
import subprocess

from diode_send import make_modbus_reader, run_sender, MODBUS_HOST, MODBUS_PORT, DIODE_HOST, DIODE_PORT

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    # start the honeynet-facing receive side as its own process. it binds
    # the diode port and forwards into MQTT. separate process on purpose:
    # the two halves share no python objects, only the one-way datagrams.
    recv_proc = subprocess.Popen([sys.executable, os.path.join(HERE, "diode_recv.py")])

    # if someone kills this process with a plain terminate, still run the
    # finally block below so the child does not get orphaned
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))

    print(f"bridge: Modbus {MODBUS_HOST}:{MODBUS_PORT}  ->  diode UDP {DIODE_HOST}:{DIODE_PORT}  ->  MQTT", flush=True)

    try:
        # the plant-facing send side runs here, in the parent
        run_sender(make_modbus_reader())
    finally:
        recv_proc.terminate()
        recv_proc.wait()


if __name__ == "__main__":
    main()
