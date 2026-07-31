"""
adversary_bot.py -- an automated attacker that GRADES a honeypot.

It plays a full attacker campaign against one target device and decides:
  - Does it look ALIVE (like a real running plant) or FROZEN (an obvious fake)?
  - Can I fingerprint it as a honeypot from its behaviour?
  - Can I crash it? (a dead honeypot is useless)
  - Does it stay reachable and keep answering while I attack it?
Then it prints a scorecard with an overall grade and writes a report file.

  .venv/bin/python adversary_bot.py [host] [port] [baseline_port]   (windows: .venv/Scripts/python.exe)
  default: 127.0.0.1 5101   baseline 5022

Idea: a strong honeynet is EASY to attack (it is a lure) but HARD to detect
and HARD to crash. This bot measures exactly that, so you can prove the project
is good -- or find what to fix.
"""

import os
import sys
import time
import socket
import struct
import statistics

from pymodbus.client import ModbusTcpClient

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5101
baseline_port = int(sys.argv[3]) if len(sys.argv) > 3 else 5022

READS = 12


# ---------- low-level Modbus helpers ----------
def modbus_read_frame(unit=1, start=0, qty=6, txid=1):
    """A valid Modbus/TCP 'read holding registers' request frame."""
    pdu = struct.pack(">BHH", 0x03, start, qty)
    mbap = struct.pack(">HHHB", txid, 0, len(pdu) + 1, unit)
    return mbap + pdu


def read_series(h, p, n=READS, delay=1.0):
    """Read the registers n times; return (list_of_value_tuples, list_of_latencies_ms)."""
    client = ModbusTcpClient(h, port=p, timeout=2)
    if not client.connect():
        return None, None
    vals, lats = [], []
    for _ in range(n):
        t = time.perf_counter()
        rr = client.read_holding_registers(0, count=6)
        lat = (time.perf_counter() - t) * 1000
        if not rr.isError():
            vals.append(tuple(rr.registers))
            lats.append(lat)
        time.sleep(delay)
    client.close()
    return vals, lats


def is_alive(h, p):
    """True if the device is reachable and answers a read correctly."""
    client = ModbusTcpClient(h, port=p, timeout=2)
    ok = client.connect()
    good = False
    if ok:
        rr = client.read_holding_registers(0, count=2)
        good = not rr.isError()
    client.close()
    return good


def try_write(h, p, value=1234):
    """Attempt an unauthorised write (Modbus has no auth). Return 'accepted'/'refused'/'error'."""
    client = ModbusTcpClient(h, port=p, timeout=2)
    if not client.connect():
        return "unreachable"
    try:
        rr = client.write_register(0, value)
        result = "refused" if rr.isError() else "accepted"
    except Exception:
        result = "error"
    client.close()
    return result


def malformed_probe(h, p):
    """Send a junk / bad-function-code frame, then check the device is still alive."""
    try:
        s = socket.create_connection((h, p), timeout=2)
        s.sendall(b"\x00\x01\x00\x00\x00\x06\x01\x99\xff\xff\x00\x99")  # bad fn code + junk
        s.settimeout(2)
        try:
            s.recv(256)
        except Exception:
            pass
        s.close()
    except OSError:
        pass
    time.sleep(0.5)
    return is_alive(h, p)


def flood(h, p, n=250):
    """Fire-and-forget connection flood (no recv, so we never hang). Return sockets sent."""
    frame = modbus_read_frame()
    sent = 0
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.3)
            s.connect((h, p))
            s.sendall(frame)
            sent += 1
        except OSError:
            pass
        finally:
            s.close()          # close it even if the connect failed, or we leak handles
    return sent


def clamp(x, lo=0, hi=100):
    return max(lo, min(hi, int(round(x))))


# ---------- the campaign ----------
def grade_level_movement(vals):
    """Return (distinct_count, level_stdev) for the water level (register 0, x10)."""
    if not vals:
        return 0, 0.0
    distinct = len(set(vals))
    levels = [v[0] / 10.0 for v in vals]
    stdev = statistics.pstdev(levels) if len(levels) > 1 else 0.0
    return distinct, stdev


def main():
    lines = []

    def out(s=""):
        print(s, flush=True)
        lines.append(s)

    out("=" * 64)
    out("  ADVERSARY BOT  --  automated attack + honeypot grading")
    out("=" * 64)
    out(f"  Target:   {host}:{port}")
    out(f"  Baseline: {host}:{baseline_port}  (a plain static honeypot, for contrast)")
    out("")

    # [1] RECON
    if not is_alive(host, port):
        out(f"[1] RECON        target {host}:{port} is NOT answering. Is the fleet running?")
        starter = ".\\demo.bat" if sys.platform.startswith("win") else "./demo.sh"
        out(f"    -> start it with:  {starter}   (or run_fleet.py)")
        return
    out("[1] RECON        port open, Modbus answering .............. OK (device reachable)")

    # [2] BELIEVABILITY
    vals, lats = read_series(host, port)
    distinct, stdev = grade_level_movement(vals)
    moves = stdev >= 0.3
    out(f"[2] BELIEVABILITY  read {READS}x -> {distinct} distinct readings, level stdev {stdev:.2f}")
    if moves:
        out("     verdict: LOOKS LIVE  (a real plant drifts) -> deception holds")
    else:
        out("     verdict: FROZEN  (values never move) -> an attacker sees it is FAKE")

    # baseline contrast
    b_vals, _ = read_series(host, baseline_port, n=5, delay=0.3)
    if b_vals:
        b_distinct, b_stdev = grade_level_movement(b_vals)
        out(f"     baseline static: {b_distinct} distinct, stdev {b_stdev:.2f}  "
            f"({'moves' if b_stdev >= 0.3 else 'frozen -> obviously fake'})")

    # [3] FINGERPRINT (behavioural honeypot detection)
    lat_stdev = statistics.pstdev(lats) if lats and len(lats) > 1 else 0.0
    detected_fake = not moves  # frozen values are the classic give-away
    out(f"[3] FINGERPRINT   tried to detect a honeypot from behaviour "
        f"(latency stdev {lat_stdev:.1f} ms)")
    if detected_fake:
        out("     -> DETECTED as fake (frozen values). Weak deception.")
    else:
        out("     -> could NOT confirm it is fake from its behaviour. Deception holds.")

    # [4] AGGRESSION
    write_result = try_write(host, port)
    out(f"[4] AGGRESSION    unauthorised write of 1234 -> {write_result}  "
        f"(Modbus has no auth; this should be LOGGED by the target)")

    # [5] RESILIENCE
    survived_malformed = malformed_probe(host, port)
    out(f"[5] RESILIENCE    malformed frame: {'survived' if survived_malformed else 'CRASHED / stopped answering'}")
    sent = flood(host, port, n=250)
    time.sleep(1.0)
    survived_flood = is_alive(host, port)
    out(f"                  flood {sent} connections: "
        f"{'survived, still answering' if survived_flood else 'CRASHED / stopped answering'}")

    # ---------- scores ----------
    # deception = how alive it looks. Movement (stdev) is the real signal an
    # attacker uses; a frozen plant (stdev ~0, like the static baseline) is the
    # dead give-away. Distinct-read variety is only a small bonus.
    if moves:
        move_score = min(stdev, 2.0) / 2.0 * 90     # ~2.0 stdev = clearly a live plant
        variety = 10 if distinct >= 3 else (distinct / 3.0) * 10
        deception = clamp(move_score + variety)
    else:
        deception = clamp(stdev / 0.3 * 20)          # frozen / barely moving -> very low

    if not moves:
        detection_resistance = 20            # frozen = one big tell
    elif survived_malformed:
        detection_resistance = 85            # believable, but "only Modbus" is a residual tell
    else:
        detection_resistance = 55

    if survived_malformed and survived_flood:
        resilience = 100
    elif survived_malformed or survived_flood:
        resilience = 60
    else:
        resilience = 10

    overall = (deception + detection_resistance + resilience) / 3
    grade = ("A" if overall >= 85 else "B" if overall >= 70 else
             "C" if overall >= 55 else "D" if overall >= 40 else "F")

    out("")
    out("-" * 64)
    out("  SCORES")
    out(f"    Deception (believability) .......... {deception:3d} / 100")
    out(f"    Detection resistance ............... {detection_resistance:3d} / 100")
    out(f"    Resilience (survives attack) ....... {resilience:3d} / 100")
    out(f"    OVERALL GRADE ...................... {grade}   (avg {overall:.0f}/100)")
    out("=" * 64)
    out("  How to read this:")
    out("  I attacked this device like a real adversary. A GOOD honeynet")
    out("  behaves like a live plant (high deception), cannot be crashed")
    out("  (high resilience), and does not give itself away (high detection")
    out("  resistance). A WEAK project scores low on deception (frozen values)")
    out("  or resilience (it crashes). Every action above should appear in")
    out("  the defender's dashboard/logs -- that is your detection coverage.")
    out("=" * 64)

    # write report
    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analysis")
    report = os.path.join(report_dir, "adversary_report.txt")
    try:
        os.makedirs(report_dir, exist_ok=True)
        with open(report, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"\n[report saved: {report}]", flush=True)
    except OSError:
        pass


if __name__ == "__main__":
    main()
