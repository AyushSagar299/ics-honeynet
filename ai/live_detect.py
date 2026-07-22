"""
live_detect.py -- run the SMART detector LIVE against the plant.

It loads the trained model (ai/detector.joblib), reads the plant's telemetry
every second, and prints NORMAL or ANOMALY with a score. In another terminal,
do an attacker write and watch the brain flag it:

   .venv\\Scripts\\python.exe attacker\\scripts\\write_register.py 127.0.0.1 5020

  python live_detect.py [host] [port]     default 127.0.0.1 5020  (the real plant)
"""

import os
import sys
import time

import numpy as np
import joblib
from pymodbus.client import ModbusTcpClient

HERE = os.path.dirname(os.path.abspath(__file__))
host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5020

bundle = joblib.load(os.path.join(HERE, "detector.joblib"))
model, scaler = bundle["model"], bundle["scaler"]


def features(r):
    level = r[0] / 10.0
    temp = r[1] / 10.0
    pressure = r[2] / 10.0
    pump = r[3] if len(r) > 3 else 0
    heater = r[4] if len(r) > 4 else 0
    valve = r[5] if len(r) > 5 else 1
    p_res = pressure - level * 0.1
    return np.array([[level, temp, pressure, pump, heater, valve, p_res]]), (level, temp, pressure)


client = ModbusTcpClient(host, port=port, timeout=2)
if not client.connect():
    print(f"cannot connect to {host}:{port} -- start the plant first:")
    print(r"   .venv\Scripts\python.exe real-lab\process-simulator\tank_plc.py")
    sys.exit(1)

print(f"SMART detector watching {host}:{port} live.  Ctrl+C to stop.")
print(f"attack it in another terminal and watch it flag:")
print(rf"   .venv\Scripts\python.exe attacker\scripts\write_register.py {host} {port}")
print()
try:
    while True:
        rr = client.read_holding_registers(0, count=6)
        if not rr.isError():
            X, (level, temp, pressure) = features(rr.registers)
            Xs = scaler.transform(X)
            anomalous = model.predict(Xs)[0] == -1
            score = -float(model.score_samples(Xs)[0])
            tag = "*** ANOMALY -- attacker? ***" if anomalous else "normal"
            print(f"  level={level:6.1f}%  temp={temp:5.1f}C  pressure={pressure:4.1f}  "
                  f"score={score:+.2f}  {tag}", flush=True)
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    client.close()
