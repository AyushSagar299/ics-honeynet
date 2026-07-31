"""
attack_mitre_map.py -- map recorded attacker activity to MITRE ATT&CK for ICS.

It reads the honeynet's logs and tags each kind of attacker action with the
MITRE ATT&CK for ICS technique it corresponds to, then prints a summary and
saves a report. This turns raw logs into the standard vocabulary that OT
security teams expect.

  .venv/bin/python analysis/attack_mitre_map.py        (run an attack first so the logs exist)
"""

import os
import json
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
FLEET = os.path.join(HERE, "..", "honeynet", "fleet")
CONN = os.path.join(FLEET, "connections.log")
ACT = os.path.join(FLEET, "actions.log")

# attacker action -> (technique id, name, tactic)  [MITRE ATT&CK for ICS]
EVENT_MAP = {
    "probe": ("T0846", "Remote System Discovery", "Discovery"),
    "read":  ("T0801", "Monitor Process State", "Collection"),
    "write": ("T0836", "Modify Parameter", "Impair Process Control"),
}
CMD = ("T0855", "Unauthorized Command Message", "Impair Process Control")
DOS = ("T0814", "Denial of Service", "Inhibit Response Function")


def load(path):
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
    return rows


def main():
    conns = load(CONN)
    acts = load(ACT)
    techniques = collections.Counter()

    for a in acts:
        ev = a.get("event")
        if ev in EVENT_MAP:
            techniques[EVENT_MAP[ev]] += 1
            if ev == "write":                       # a write is also an unauthorised command
                techniques[CMD] += 1

    per_ip = collections.Counter(c.get("ip") for c in conns)
    for ip, n in per_ip.items():
        if n >= 50:                                 # many connections from one source = DoS
            techniques[DOS] += 1

    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out("=" * 72)
    out("  ATTACKER ACTIVITY MAPPED TO MITRE ATT&CK FOR ICS")
    out("=" * 72)
    out(f"  source logs: {len(conns)} connections, {len(acts)} recorded actions")
    out("-" * 72)
    if not techniques:
        out("  no attacker activity in the logs yet -- run an attack first.")
    else:
        out(f"  {'Technique':10}{'Name':34}{'Tactic':22}{'seen':>5}")
        for (tid, name, tactic), cnt in sorted(techniques.items(), key=lambda x: -x[1]):
            out(f"  {tid:10}{name:34}{tactic:22}{cnt:>5}")
    out("=" * 72)
    out("  Every attacker action on a decoy is now tagged with a standard")
    out("  ATT&CK-for-ICS technique -- ready for the report and the SOC.")
    out("=" * 72)

    with open(os.path.join(HERE, "attack_mitre_map.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
