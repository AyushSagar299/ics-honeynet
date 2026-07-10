"""
dpi_listener.py  --  a passive Deep Packet Inspection listener for Modbus.

It reads the network traffic and prints, in plain English, what each Modbus
message is doing (which registers are read, what values come back, any writes).
This is the "DPI probe" from the internship tasks.

IMPORTANT: this is PASSIVE. It only reads packets. It never sends anything,
so it can never disturb the PLC or the plant.

Two ways to run it:

  # 1. read a capture file (no sudo needed) -- good for testing
  python dpi_listener.py sample_modbus.pcap

  # 2. sniff live traffic (needs sudo, and the real lab running)
  sudo ../../.venv/bin/python dpi_listener.py live lo0 5020
"""

import sys
import struct
from datetime import datetime

from scapy.all import rdpcap, sniff, TCP, IP, Raw

# the Modbus function codes we might see (the number -> a human name)
FUNCTION_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x10: "Write Multiple Registers",
}

# our tank's register map, so we can show meaning, not just numbers
TANK_REGISTERS = ["level(%)", "temp(C)", "pressure(bar)", "pump", "heater", "valve"]

# remember each request by its transaction id, so when the reply comes back
# we know which registers it was asking about
pending = {}


def decode_tank(start, values):
    """Turn a list of register values into readable tank fields."""
    parts = []
    for i, value in enumerate(values):
        reg = start + i
        if reg < len(TANK_REGISTERS):
            label = TANK_REGISTERS[reg]
            if label in ("level(%)", "temp(C)", "pressure(bar)"):
                parts.append(f"{label}={value / 10:.1f}")   # these were stored x10
            else:
                parts.append(f"{label}={value}")
    return "  ".join(parts)


def inspect_packet(pkt, plc_port):
    """Look at one packet and, if it is Modbus, print what it is doing."""
    # we only care about TCP packets that actually carry data
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    data = bytes(pkt[Raw].load)
    if len(data) < 8:
        return                       # too short to be a Modbus message

    # the Modbus TCP header (MBAP): transaction id, protocol id, length, unit
    trans_id, proto_id, length, unit = struct.unpack(">HHHB", data[:7])
    if proto_id != 0:
        return                       # protocol id 0 means Modbus; skip anything else
    func = data[7]                   # the function code comes right after

    src = pkt[IP].src
    dst = pkt[IP].dst
    # traffic going TO the PLC's port is a request; coming FROM it is a reply
    is_request = (pkt[TCP].dport == plc_port)
    when = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S")
    name = FUNCTION_NAMES.get(func, f"function {func:#04x}")

    # --- read holding registers (function 3) ---
    if func == 0x03 and is_request:
        start, count = struct.unpack(">HH", data[8:12])
        pending[trans_id] = (start, count)
        print(f"{when}  {src} -> {dst}   READ  {name}: regs {start}..{start + count - 1}")

    elif func == 0x03 and not is_request:
        byte_count = data[8]
        raw_values = data[9:9 + byte_count]
        values = [v[0] for v in struct.iter_unpack(">H", raw_values)]
        start = pending.get(trans_id, (0, len(values)))[0]
        meaning = decode_tank(start, values)
        print(f"{when}  {src} -> {dst}   VALUES {values}   {meaning}")

    # --- write single register (function 6) ---
    elif func == 0x06:
        addr, value = struct.unpack(">HH", data[8:12])
        arrow = "WRITE " if is_request else "write-ok"
        print(f"{when}  {src} -> {dst}   {arrow} {name}: reg {addr} = {value}")

    # --- anything else: just say what it was ---
    else:
        side = "request " if is_request else "reply   "
        print(f"{when}  {src} -> {dst}   {side} {name}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        raise SystemExit(0)

    if args[0] == "live":
        # live sniffing: needs sudo. give the interface and the port.
        iface = args[1]
        port = int(args[2])
        print(f"Listening on {iface} for Modbus on port {port}. Ctrl+C to stop.")
        print("PASSIVE: this only reads packets, it never sends anything.\n")
        sniff(iface=iface, filter=f"tcp port {port}", store=False,
              prn=lambda p: inspect_packet(p, port))
    else:
        # read a capture file
        pcap_file = args[0]
        port = int(args[1]) if len(args) > 1 else 502
        print(f"Reading {pcap_file}  (treating port {port} as the PLC)\n")
        for pkt in rdpcap(pcap_file):
            inspect_packet(pkt, port)
