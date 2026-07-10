"""
Scenario 1 -- Reconnaissance.

Scan a target with nmap to see what it looks like from the outside: is the port
open, what service does it seem to be, and does the Modbus fingerprint script
get a response. This is the first thing a real attacker does.

  python recon.py <host> <port>
"""

import sys
import subprocess

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = sys.argv[2] if len(sys.argv) > 2 else "5021"

print(f"[recon] nmap port scan + Modbus fingerprint of {host}:{port}")
# note: we skip -sV (version detection) because it hangs for ~40s on a bare
# Modbus port. On the real honeynet (port 502) nmap labels this 'modbus';
# on the laptop test port it just shows the port open.
cmd = ["nmap", "-Pn", "-sT", "-p", port,
       "--script", "modbus-discover", "--script-timeout", "20s", host]
print("       ", " ".join(cmd))
subprocess.run(cmd)
