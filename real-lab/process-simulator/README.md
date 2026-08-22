# Process simulator — Stage A (the water-tank PLC)

This is the **data source** for the whole project: a fake water tank whose
values move like real physics, served over **Modbus TCP** exactly like a real PLC.
Everything downstream (the passive listener, the bridge, the digital twin, the
decoys) just reads these registers.

## Files
- `tank_plc.py` — the simulator + Modbus server (run this).
- `read_test.py` — a tiny client that reads the values 3 times to prove it works.
- `requirements.txt` — pinned `pymodbus==3.6.9` (newer 3.13 broke the classic API).
- `Dockerfile` — runs this same file in the Docker lab on port 502 (see `../README.md`).

## What the plant does
A 1000 litre water tank with a fill pump, a heater and an outlet valve. The
physics is meant to look like real hardware, not a straight line: the outlet
drains faster when the tank is fuller (Torricelli), there is a daily demand
cycle for the water, the temperature eases towards a target instead of jumping,
and every reading gets a little sensor noise. The PLC runs hysteresis control in
`auto` mode and obeys the coils in `manual` mode, with a couple of safety
interlocks (no heater on a near-empty tank, shut the outlet before it empties).
It also answers all four Modbus function codes and a device-identification probe
(a Schneider Modicon M340 identity), so it fingerprints like a real controller.

## Register map (holding registers)
HR0–HR5 are the frozen contract — the bridge, twin and decoys depend on them, so
they never change. HR6+ were added later and are safe to ignore or read.

| Reg | Meaning | Encoding |
|-----|---------|----------|
| HR0 | water level | percent × 10 (502 → 50.2 %) |
| HR1 | temperature | °C × 10 (235 → 23.5 °C) |
| HR2 | pressure | bar × 10 |
| HR3 | pump | 0 = off, 1 = on |
| HR4 | heater | 0 = off, 1 = on |
| HR5 | valve | 0 = closed, 1 = open |
| HR6 | inflow | litres/min × 10 |
| HR7 | outflow | litres/min × 10 |
| HR8 | stored volume | litres |
| HR9 | level setpoint low | percent × 10 (writable) |
| HR10 | level setpoint high | percent × 10 (writable) |
| HR11 | temp setpoint low | °C × 10 (writable) |
| HR12 | temp setpoint high | °C × 10 (writable) |
| HR13 | control mode | 0 = auto, 1 = manual (writable) |
| HR14 | alarm word | bitmask (hi/lo level, hi temp, dry-run, lo temp) |
| HR15 | pump runtime | seconds (wraps at 65535) |
| HR16 | scan counter | +1 every scan — proves the PLC is live |
| HR17 | ambient temp | °C × 10 |

It also serves **coils** (pump/heater/valve command, run, alarm-ack — the write
surface an attacker can poke), **discrete inputs** (pump/heater/valve running,
the alarm bits, auto-mode) and **input registers** (level, temp, pressure,
inflow, outflow, ambient). See the header of `tank_plc.py` for the full list.

## How to run (on the laptop)
```bash
# one-time: make the virtual environment and install pymodbus
python3 -m venv ../../.venv
../../.venv/bin/pip install -r requirements.txt

# terminal 1 — start the tank PLC (Modbus on port 5020)
../../.venv/bin/python tank_plc.py

# terminal 2 — read it back
../../.venv/bin/python read_test.py
```

**Done when:** `read_test.py` shows *different* numbers each time — the values are
alive — and prints the coils / discrete inputs / input registers at the end.

## Notes
- Port is `5020` on the laptop because the real Modbus port `502` needs `sudo`.
  Inside Docker we run it on `502` by setting `MODBUS_PORT=502`.
- Stage B (later): OpenPLC replaces this server and runs the control logic, but
  it still speaks Modbus on the same port, so nothing after this has to change.
