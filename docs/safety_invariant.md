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
The invariant is checked automatically by `analysis/zero_egress_test.py`. It runs
a full attack against a decoy (reads, unauthorised writes, a malformed frame and a
connection flood) and asserts that zero connections reach the OT endpoint. The test
first performs a control step (a deliberate connection that IS detected), to prove
it is not a blind test. Current result: PASS -- zero egress during a full attack.
