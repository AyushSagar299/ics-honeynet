# The attacker (Month 3)

You play the attacker against your **own** decoys, to measure two things: is the
live decoy believable, and did the logging catch the attack. Everything here is
run only against your own honeynet, never against anything you do not own.

## The five scenarios (`scripts/`)
| # | Script | What it does | What it shows |
|---|--------|--------------|---------------|
| 1 | `recon.py` | nmap port scan + Modbus fingerprint | the device is discoverable |
| 2 | `read_registers.py` | read registers 3× | **LIVE decoy moves, STATIC decoy frozen** |
| 3 | `write_register.py` | write a register + coil | Modbus has no auth; write is logged |
| 4 | `bruteforce_hmi.py` | password list vs the HMI login | every attempt logged |
| 5 | `replay.py` | replay + a malformed frame | decoy is robust, odd traffic captured |

Run them all with the comparison built in:
```bash
../.venv/bin/python scripts/run_all.py
```

## Result from a real run
```
Scenario 2  LIVE decoy   -> 3 distinct readings -> LIVE (looks like a real plant)
Scenario 2  STATIC decoy -> 1 distinct reading  -> STATIC (gives itself away)
Scenario 3  write register 0 = 1234 accepted, and logged by the decoy
Scenario 4  16 login attempts, all logged with source IP
Scenario 5  decoy survived a malformed frame and kept answering
```
That Scenario-2 contrast is the core evidence for the project.

## The isolated network (the real deployment)
In the full lab there are three Docker networks. The attacker sits on its own
and can reach only the honeynet:
```
attacker-net 10.30.0.0/24  --can reach-->  honeynet-net 10.20.0.0/24
                                            (NO path to real-lab-net 10.10.0.0/24)
```
Create them and run the attacker container on the attacker side:
```bash
docker network create --subnet=10.30.0.0/24 attacker-net
docker build -t honeynet-attacker .
docker run --rm -it --network attacker-net honeynet-attacker
```
The decoys attach to `honeynet-net`; the real lab stays on `real-lab-net` with no
route from the attacker. (We already proved the one-way mirror at the app level:
a write to the decoy never reached the real PLC.)

> On the laptop we test against the decoys' host ports (5021/5022/8090) for
> speed. The container + network wiring above is the "proper" isolated setup.
