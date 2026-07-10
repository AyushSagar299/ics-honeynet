"""
Scenario 5 -- Replay and robustness probe.

Re-send a recorded Modbus request at the decoy, then send a malformed frame, and
finally read again to check the decoy is still alive. This tests how the decoy
copes with unusual input (a real device should not crash) and that the odd
traffic is captured.

  python replay.py <host> <port>
"""

import sys
import socket
import struct

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5021


def send(raw, label):
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(raw)
        try:
            reply = s.recv(256)
        except socket.timeout:
            reply = b""
        s.close()
        print(f"        {label}: sent {len(raw)} bytes, got {len(reply)} back "
              + (reply.hex() if reply else "(no reply)"))
        return reply
    except OSError as e:
        print(f"        {label}: connection failed ({e})")
        return b""


print(f"[replay] probing {host}:{port}")

# a normal 'read holding registers 0..5' request, replayed
good = struct.pack(">HHHB", 1, 0, 6, 1) + struct.pack(">BHH", 3, 0, 6)
send(good, "replayed read ")

# a malformed frame (the length field lies) -- does the decoy survive it?
send(struct.pack(">HHHB", 2, 0, 99, 1) + b"\x03\x00\x00", "malformed   ")

# read again: if we still get a reply, the decoy shrugged off the bad input
alive = send(struct.pack(">HHHB", 3, 0, 6, 1) + struct.pack(">BHH", 3, 0, 6), "read again  ")
print("[replay] decoy still responding after malformed input:", len(alive) > 0)
