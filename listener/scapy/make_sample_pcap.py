"""
make_sample_pcap.py  --  build a small pcap of REAL Modbus traffic.

Why this exists: to test the DPI listener and Zeek you need a capture file,
but capturing live traffic on a Mac needs sudo (and later, Docker). This
script writes a pcap full of real Modbus bytes so you can run and check the
tools straight away. When your real lab is running you replace this with a
real capture (see the README) and run the exact same tools on it.

The traffic it fakes = an engineering workstation (10.10.0.20) opening one
TCP connection to the tank PLC (10.10.0.10) on Modbus port 502, reading the
6 tank registers about once a second, plus one HMI write near the end.

It uses a proper TCP handshake and growing sequence numbers, otherwise Zeek
thinks the repeated packets are retransmissions and ignores them.
"""

import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

PLC = "10.10.0.10"      # the tank PLC (server)
WS = "10.10.0.20"       # the workstation reading it (client)
PORT = 502              # real Modbus port
SPORT = 51000           # the client's port

# TCP sequence numbers for each side. They must grow by the number of data
# bytes sent, so we keep them in one small dict and update as we go.
tcp = {"cseq": 1001, "sseq": 5001}


# --- small helpers that build the Modbus bytes by hand ---

def mbap(trans_id, unit_id, pdu):
    """Modbus TCP header (MBAP) + the PDU. length = unit byte + pdu bytes."""
    length = 1 + len(pdu)
    return struct.pack(">HHHB", trans_id, 0, length, unit_id) + pdu


def read_request(start, count):
    return struct.pack(">BHH", 0x03, start, count)     # function 0x03


def read_response(values):
    body = b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">BB", 0x03, len(body)) + body


def write_request(addr, value):
    return struct.pack(">BHH", 0x06, addr, value)      # function 0x06


# --- helpers that build the TCP/IP packets and track sequence numbers ---

def client_to_plc(payload, t):
    pkt = (Ether() / IP(src=WS, dst=PLC) /
           TCP(sport=SPORT, dport=PORT, flags="PA", seq=tcp["cseq"], ack=tcp["sseq"]) /
           Raw(payload))
    pkt.time = t
    tcp["cseq"] += len(payload)
    return pkt


def plc_to_client(payload, t):
    pkt = (Ether() / IP(src=PLC, dst=WS) /
           TCP(sport=PORT, dport=SPORT, flags="PA", seq=tcp["sseq"], ack=tcp["cseq"]) /
           Raw(payload))
    pkt.time = t
    tcp["sseq"] += len(payload)
    return pkt


# --- build the conversation ---

packets = []
t = 1751850000.0        # a starting time (epoch seconds)

# 1. the TCP three-way handshake (SYN, SYN-ACK, ACK). We give these times just
# before the first read so the whole capture stays in time order (otherwise
# Zeek sees time jump backwards and stamps every event with the same time).
syn = Ether() / IP(src=WS, dst=PLC) / TCP(sport=SPORT, dport=PORT, flags="S", seq=1000)
syn.time = t
synack = Ether() / IP(src=PLC, dst=WS) / TCP(sport=PORT, dport=SPORT, flags="SA", seq=5000, ack=1001)
synack.time = t + 0.01
ack = Ether() / IP(src=WS, dst=PLC) / TCP(sport=SPORT, dport=PORT, flags="A", seq=1001, ack=5001)
ack.time = t + 0.02
packets += [syn, synack, ack]
t += 1.0                # first read one second after the connection opens

# 2. six read cycles, about one second apart. the values drift like the tank.
trans = 0
level = 50.2
temp = 23.5
for i in range(6):
    trans += 1
    packets.append(client_to_plc(mbap(trans, 1, read_request(0, 6)), t))
    values = [
        int(level * 10),            # level
        int(temp * 10),             # temp
        int(level * 0.1 * 10),      # pressure
        1 if level < 60 else 0,     # pump
        1,                          # heater
        1,                          # valve
    ]
    packets.append(plc_to_client(mbap(trans, 1, read_response(values)), t + 0.02))
    level -= 0.7                    # tank drains
    temp += 0.3                     # heater warms it
    t += 1.0                        # next poll ~1 s later

# 3. one write at the end: the HMI sets a pump setpoint (register 10 = 1)
trans += 1
packets.append(client_to_plc(mbap(trans, 1, write_request(10, 1)), t))
packets.append(plc_to_client(mbap(trans, 1, write_request(10, 1)), t + 0.02))

wrpcap("sample_modbus.pcap", packets)
print(f"wrote sample_modbus.pcap  ({len(packets)} packets)")
