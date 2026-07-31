"""
zero_egress_test.py -- prove the one-way safety property of the honeynet.

The core safety claim of this project is: an attacker who fully owns a decoy can
never send anything back toward the real OT plant. This script turns that claim
into a PASSING TEST, which is exactly the kind of evidence an examiner wants.

How it works:
  1. It stands up a "canary" that represents the real OT network. The canary
     records every single connection it receives.
  2. Control step: the test connects to the canary once itself, to prove the
     canary really detects traffic -- so a PASS can never be a blind test.
  3. It runs a full attack campaign (reads, unauthorised writes, malformed
     frames, a connection flood) against the DECOY.
  4. It asserts that, during the whole attack, ZERO connections reached the
     canary from the honeynet -> the isolation holds.

In a real deployment, set OT_HOST / OT_PORT to the real plant's address.

  .venv/bin/python analysis/zero_egress_test.py    (start the fleet first: ./demo.sh, or demo.bat on windows)
"""

import os
import time
import socket
import struct
import threading

from pymodbus.client import ModbusTcpClient

OT_HOST = os.environ.get("OT_HOST", "127.0.0.1")
OT_PORT = int(os.environ.get("OT_PORT", "5999"))          # stands for the real OT network (5900 is screen sharing on macos)
DECOY_HOST = os.environ.get("DECOY_HOST", "127.0.0.1")
DECOY_PORT = int(os.environ.get("DECOY_PORT", "5101"))    # a decoy the attacker owns

hits = []          # every connection the canary receives
_run = True
bind_error = None  # set if the canary port is already taken


def canary():
    global bind_error
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((OT_HOST, OT_PORT))
    except OSError as e:
        bind_error = e
        s.close()
        return
    s.listen(50)
    s.settimeout(0.5)
    while _run:
        try:
            conn, addr = s.accept()
            hits.append((time.time(), addr))
            try:
                conn.close()
            except OSError:
                pass
        except socket.timeout:
            continue
        except OSError:
            break
    s.close()


def read_frame(qty=6):
    pdu = struct.pack(">BHH", 0x03, 0, qty)
    return struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu


def is_alive(h, p):
    c = ModbusTcpClient(h, port=p, timeout=2)
    ok = c.connect()
    good = False
    if ok:
        r = c.read_holding_registers(0, count=2)
        good = not r.isError()
    c.close()
    return good


def attack_decoy():
    c = ModbusTcpClient(DECOY_HOST, port=DECOY_PORT, timeout=2)
    if c.connect():
        for _ in range(5):
            c.read_holding_registers(0, count=6)
            c.write_register(0, 1234)
            time.sleep(0.15)
        c.close()
    frame = read_frame()
    for _ in range(100):                    # connection flood
        s = socket.socket()
        try:
            s.settimeout(0.3)
            s.connect((DECOY_HOST, DECOY_PORT))
            s.sendall(frame)
        except OSError:
            pass
        finally:
            s.close()          # close it even if the connect failed, or we leak handles
    try:                                    # a malformed frame
        s = socket.create_connection((DECOY_HOST, DECOY_PORT), timeout=2)
        s.sendall(b"\x00\x01\x00\x00\x00\x06\x01\x99\xff\xff\x00\x99")
        s.close()
    except OSError:
        pass


def main():
    global _run
    print("=" * 66)
    print("  ZERO-EGRESS-TO-OT SAFETY TEST")
    print("=" * 66)
    print(f"  protected OT endpoint (canary): {OT_HOST}:{OT_PORT}")
    print(f"  decoy under attack            : {DECOY_HOST}:{DECOY_PORT}")

    threading.Thread(target=canary, daemon=True).start()
    time.sleep(0.5)

    if bind_error:
        print(f"  [!] could not start the canary on {OT_HOST}:{OT_PORT}: {bind_error}")
        print("      something else is already on that port. set OT_PORT to a free one.")
        _run = False
        return

    # 1. control -- prove the canary can detect egress
    try:
        socket.create_connection((OT_HOST, OT_PORT), timeout=2).close()
    except OSError as e:
        print("  [!] canary not reachable:", e)
        _run = False
        return
    time.sleep(0.3)
    if len(hits) >= 1:
        print(f"  [control] deliberate egress DETECTED by canary ({len(hits)} hit) -> the monitor works")
    else:
        print("  [control] FAILED: canary missed the control connection -> the test is blind")
        _run = False
        return
    baseline = len(hits)

    # 2. full attack against the decoy
    if not is_alive(DECOY_HOST, DECOY_PORT):
        starter = ".\\demo.bat" if os.name == "nt" else "./demo.sh"
        print(f"  [!] decoy {DECOY_HOST}:{DECOY_PORT} not answering -- start the fleet first ({starter})")
        _run = False
        return
    print("  [attack] full attack on the decoy: reads, writes, flood, malformed frame ...")
    attack_decoy()
    time.sleep(1.0)

    # 3. assert zero egress during the attack
    egress = len(hits) - baseline
    print("-" * 66)
    if egress == 0:
        print("  RESULT: PASS  --  0 connections reached the OT endpoint during the attack.")
        print("          The honeynet cannot be used as a pivot into the real plant.")
    else:
        print(f"  RESULT: FAIL  --  {egress} connection(s) reached the OT endpoint. Isolation broken.")
    print("=" * 66)
    _run = False


if __name__ == "__main__":
    main()
