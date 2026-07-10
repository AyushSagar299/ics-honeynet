"""
run_all.py -- run the five attack scenarios in order.

The important one is Scenario 2, run against BOTH decoys: it shows the live
decoy's values moving and the static decoy's values frozen -- the core result.

  python run_all.py
"""

import os
import sys
import subprocess

PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))

LIVE = ("127.0.0.1", "5021")
STATIC = ("127.0.0.1", "5022")
HMI = "http://127.0.0.1:8090"


def run(script, *args):
    print("\n" + "=" * 72)
    subprocess.run([PY, os.path.join(HERE, script), *args])


print("### 1. Reconnaissance (live decoy) ###")
run("recon.py", *LIVE)

print("\n### 2. Protocol enumeration -- the key comparison ###")
print("--- against the LIVE decoy ---")
run("read_registers.py", *LIVE)
print("--- against the STATIC decoy ---")
run("read_registers.py", *STATIC)

print("\n### 3. Unauthorised write (live decoy) ###")
run("write_register.py", *LIVE)

print("\n### 4. Credential brute-force (decoy HMI) ###")
run("bruteforce_hmi.py", HMI)

print("\n### 5. Replay / robustness (live decoy) ###")
run("replay.py", *LIVE)

print("\n" + "=" * 72)
print("done -- check the decoy logs for what was captured.")
