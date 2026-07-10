# Process simulator — Stage A (the water-tank PLC)

This is the **data source** for the whole project: a fake water tank whose
values move like real physics, served over **Modbus TCP** exactly like a real PLC.
Everything downstream (the passive listener, the bridge, the digital twin, the
decoys) just reads these registers.

## Files
- `tank_plc.py` — the simulator + Modbus server (run this).
- `read_test.py` — a tiny client that reads the values 3 times to prove it works.
- `requirements.txt` — pinned `pymodbus==3.6.9` (newer 3.13 broke the classic API).

## Register map (holding registers)
| Reg | Meaning | Encoding |
|-----|---------|----------|
| HR0 | water level | percent × 10 (502 → 50.2 %) |
| HR1 | temperature | °C × 10 (235 → 23.5 °C) |
| HR2 | pressure | bar × 10 |
| HR3 | pump | 0 = off, 1 = on |
| HR4 | heater | 0 = off, 1 = on |
| HR5 | valve | 0 = closed, 1 = open |

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

**Done when:** `read_test.py` shows *different* numbers each time — the values are alive.

## Notes
- Port is `5020` on the laptop because the real Modbus port `502` needs `sudo`.
  Inside Docker we run it on `502` by setting `MODBUS_PORT=502`.
- Stage B (later): OpenPLC replaces this server and runs the control logic, but
  it still speaks Modbus on the same port, so nothing after this has to change.
