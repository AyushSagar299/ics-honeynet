# Passive DPI listener (Month 1)

This is the **listen-only** part of the project. It watches the Modbus traffic
and writes down what it sees. It never sends a single packet, so it can never
disturb the PLC or the plant. This covers two internship tasks: the passive
listening module and the non-intrusive device profiling.

```
listener/
  scapy/   dpi_listener.py    -> reads Modbus and prints it in plain English
           make_sample_pcap.py -> builds a test capture of real Modbus bytes
  zeek/    run_zeek.sh        -> turns a capture into conn.log + modbus.log (JSON)
           modbus-ports.zeek  -> lets Zeek parse the port-5020 laptop test
```

## Quick start (no lab, no sudo — just to see it work)
```bash
cd scapy
../../.venv/bin/python make_sample_pcap.py         # writes sample_modbus.pcap
../../.venv/bin/python dpi_listener.py sample_modbus.pcap
cd ../zeek && ./run_zeek.sh                          # writes logs/modbus.log
```

## Capturing the REAL traffic

The tricky part of Month 1 is *where* to capture. You cannot just run the
listener "on the network" — a switch (and a Docker bridge) only sends each
device the traffic meant for it, so a bystander sees nothing.

**Now — Stage A running on the laptop (Modbus on port 5020).**
The traffic goes over the loopback interface, so capture there with sudo:
```bash
# terminal 1: start the tank PLC and a client
../real-lab/process-simulator  ->  python tank_plc.py  +  python read_test.py

# terminal 2: record the loopback traffic to a file
sudo tcpdump -i lo0 -w capture.pcap 'tcp port 5020'
# ...let it run a few seconds, then Ctrl+C

# then read it back (no sudo needed):
cd listener/scapy && ../../.venv/bin/python dpi_listener.py ../../capture.pcap 5020
cd ../zeek && zeek -r ../../capture.pcap modbus-ports.zeek LogAscii::use_json=T
```

**Later — the real lab running in Docker (Modbus on port 502).**
On a Mac, Docker runs inside a hidden Linux VM, so macOS never sees the
container traffic. You must capture from *inside* a container. The clean way is
to give the listener container the PLC's own network view:
```yaml
# in docker-compose.yml, the listener service:
network_mode: "container:tank_plc"   # share the PLC's network namespace
cap_add: [NET_RAW, NET_ADMIN]        # allowed to sniff (but our code only reads)
```
Then inside that container you sniff its interface on port 502 and see 100% of
the PLC's traffic, both directions. This is the recommended method from the guide.

## The deliverable
The one-page write-up that comes out of this is in
`docs/device-profiling-note.md` — it describes each device using only what the
capture shows, which is exactly the "non-intrusive device profiling" task.
