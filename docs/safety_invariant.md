# One-Way Safety Invariant

## The invariant
No action taken by an attacker on any decoy can ever reach the real OT plant.
Telemetry flows only from the plant toward the Digital Shadow and the decoys;
nothing ever flows back.

## Why this is the most important property
A honeypot that can be used as a way into the real plant is worse than no
honeypot at all. So the strongest property of this system is not that it is
believable, but that it is safe: the attacker-facing side must be completely
unable to influence the real equipment.

## Three independent controls (defence in depth)
The invariant is enforced by three separate controls, so that even if one is
misconfigured, the others still hold:

1. Read-only capture. The plant is observed passively (receive-only deep packet
   inspection on a SPAN port or a network tap). The capture host never sends a
   single packet to the plant.
2. One-way data flow. The Digital Shadow and the decoys only subscribe to the
   telemetry. There is no client, socket, or code path on the decoy side that
   writes toward the plant. Data moves plant -> shadow -> decoy, never the reverse.
3. Network isolation (default-deny). The decoys sit on their own isolated network,
   with a firewall rule that denies all traffic from the decoy subnet toward the
   OT subnet. Only the one-way telemetry bridge crosses the boundary, and only
   outward from the plant.

## What is built and tested here, and what is deployment guidance
To be precise about it: on the laptop, control 2 is the one that is actually built
and tested. Attacker writes on the Modbus fleet are answered locally and never
forwarded to the shared backend, the software data diode in `bridge/` has no
receive path at all (its self-test checks the source for one), and
`zero_egress_test.py` confirms nothing reaches the protected side. Controls 1 and 3
are how a real deployment should be wired (a tap or SPAN port, and a default-deny
firewall between the decoy and OT networks). `real-lab/` sets up separate Docker
networks for this, but the laptop demo runs on one host, so the zero-egress test there
shows the software construction holds, not that a physical boundary does. The diode is
a software simulation of a hardware data diode, not the real optical device.

By default the demo keeps everything on 127.0.0.1 (`demo.sh` sets `FLEET_BIND`), and the
threat dashboard only ever listens on 127.0.0.1 because it has no login. The internal
backends always stay on 127.0.0.1. Only set `FLEET_BIND=0.0.0.0` on an isolated decoy
network.

## Data-flow diagram
```
    REAL OT PLANT
        |   (passive, receive-only capture -- control 1)
        v
    DIGITAL SHADOW  --(one-way telemetry, control 2)-->  DECOYS
        ^                                                   |
        |           default-deny firewall (control 3)       |
        +----------------  NO PATH BACK  <-------------------+

    An attacker can fully own a decoy, but still cannot reach the plant.
```

## How the invariant is verified
I check it automatically with `analysis/zero_egress_test.py`. It runs a full attack
against a decoy (reads, unauthorised writes, a malformed frame and a connection
flood) and asserts that zero connections reach the OT endpoint. It first does a
control step, a deliberate connection that is detected, so I know it is not a blind
test. Current result: PASS, zero egress during a full attack.

To run it, macOS or Linux:

```bash
.venv/bin/python analysis/zero_egress_test.py
```

Windows PowerShell:

```powershell
.venv\Scripts\python.exe analysis\zero_egress_test.py
```

Start the fleet first (`bash demo.sh`, or `demo.bat` on Windows), otherwise it tells
you the decoy is not answering and stops. It defaults to the local decoy on 5101 and
a canary on 5999. To point it somewhere else set OT_HOST, OT_PORT, DECOY_HOST and
DECOY_PORT first (`export VAR=...` in zsh, `$env:VAR="..."` in PowerShell).
