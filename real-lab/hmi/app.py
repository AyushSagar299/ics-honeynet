"""
app.py -- the plant's little operator HMI (Flask).

A real site always has some web HMI hanging off the plant network, so the lab
has one too. It reads the tank PLC over Modbus on every request and shows the
state of the plant, refreshing itself every 2 seconds. It is deliberately
plain, because plant HMIs are plain. /status returns the same data as JSON
(that is what the engineering-workstation traffic polls, and it is handy for
scripts).
"""

import os

from flask import Flask, jsonify
from pymodbus.client import ModbusTcpClient

PLC_HOST = os.environ.get("PLC_HOST", "10.10.0.10")
PLC_PORT = int(os.environ.get("PLC_PORT", "502"))

app = Flask(__name__)

ALARM_NAMES = ["HIGH LEVEL", "LOW LEVEL", "HIGH TEMP", "DRY-RUN", "LOW TEMP"]


def read_plant():
    """Read HR0..HR17 from the PLC. Returns the raw registers, or None if the
    PLC is unreachable (the HMI must still render a page then, like a real
    HMI shows 'communication lost' instead of crashing)."""
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=2)
    if not client.connect():
        return None
    r = client.read_holding_registers(0, count=18)
    client.close()
    if r.isError():
        return None
    return r.registers


def decode(regs):
    """The raw registers as named real-world values (same map as tank_plc.py)."""
    return {
        "level": regs[0] / 10, "temp": regs[1] / 10, "pressure": regs[2] / 10,
        "pump": regs[3], "heater": regs[4], "valve": regs[5],
        "inflow": regs[6] / 10, "outflow": regs[7] / 10, "volume": regs[8],
        "sp_level_low": regs[9] / 10, "sp_level_high": regs[10] / 10,
        "sp_temp_low": regs[11] / 10, "sp_temp_high": regs[12] / 10,
        "mode": "auto" if regs[13] == 0 else "manual",
        "alarms": [ALARM_NAMES[i] for i in range(5) if regs[14] & (1 << i)],
        "pump_hours": round(regs[15] / 3600, 2),
        "scan": regs[16], "ambient": regs[17] / 10,
    }


PAGE = """<!doctype html>
<html><head><title>Water Plant HMI</title>
<meta http-equiv="refresh" content="2">
<style>
  body {{ font-family: Arial, sans-serif; background: #e8e8e8; margin: 2em; }}
  h1 {{ font-size: 1.3em; }}
  table {{ border-collapse: collapse; background: white; }}
  td, th {{ border: 1px solid #999; padding: 6px 14px; text-align: left; }}
  .on {{ background: #b6e3b6; }} .off {{ background: #ddd; }}
  .alarm {{ background: #e37c7c; font-weight: bold; }}
  .footer {{ color: #666; font-size: 0.8em; margin-top: 1em; }}
</style></head><body>
<h1>Water tank -- overview</h1>
{body}
<p class="footer">PLC {plc} &middot; page refreshes every 2 s</p>
</body></html>"""


def onoff(v):
    return '<td class="on">ON</td>' if v else '<td class="off">OFF</td>'


@app.route("/")
def index():
    regs = read_plant()
    if regs is None:
        body = '<p class="alarm">COMMUNICATION LOST -- cannot reach the PLC</p>'
        return PAGE.format(body=body, plc=f"{PLC_HOST}:{PLC_PORT}")
    d = decode(regs)
    alarms = " ".join(f'<span class="alarm">{a}</span>' for a in d["alarms"]) or "none"
    body = f"""
<table>
<tr><th>Level</th><td>{d['level']:.1f} %</td><th>Pump</th>{onoff(d['pump'])}</tr>
<tr><th>Temperature</th><td>{d['temp']:.1f} &deg;C</td><th>Heater</th>{onoff(d['heater'])}</tr>
<tr><th>Pressure</th><td>{d['pressure']:.2f} bar</td><th>Valve</th>{onoff(d['valve'])}</tr>
<tr><th>Inflow</th><td>{d['inflow']:.0f} l/min</td><th>Mode</th><td>{d['mode']}</td></tr>
<tr><th>Outflow</th><td>{d['outflow']:.0f} l/min</td><th>Volume</th><td>{d['volume']} L</td></tr>
<tr><th>Level setpoints</th><td>{d['sp_level_low']:.0f} / {d['sp_level_high']:.0f} %</td>
    <th>Temp setpoints</th><td>{d['sp_temp_low']:.0f} / {d['sp_temp_high']:.0f} &deg;C</td></tr>
<tr><th>Pump hours</th><td>{d['pump_hours']}</td><th>Ambient</th><td>{d['ambient']:.1f} &deg;C</td></tr>
<tr><th>Alarms</th><td colspan="3">{alarms}</td></tr>
</table>"""
    return PAGE.format(body=body, plc=f"{PLC_HOST}:{PLC_PORT}")


@app.route("/status")
def status():
    regs = read_plant()
    if regs is None:
        return jsonify({"error": "cannot reach the PLC"}), 503
    out = decode(regs)
    out["registers"] = list(regs)      # the raw registers too, like before
    return jsonify(out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("HMI_PORT", "5000")))
