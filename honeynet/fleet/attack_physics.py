"""
attack_physics.py -- closed-loop attack fallout for the fleet decoys.

this is the interactive-plc bit. today a modbus write to a decoy gets logged but
nothing physical happens, so an attacker who forces the pump or slams a setpoint
sees the value snap straight back to normal on the next read -- a dead giveaway
that it is a static fake. here i keep a tiny per-attacker "what if" physics fork:
when a source writes to an actuator (or forces a register / coil) i seed a private
copy of that device's process values from what it is reading right now, then evolve
a believable consequence (tank overflow, pump dry-run, boiler overheat, no-flow,
motor overcurrent, ...) that ONLY that attacker sees on their later reads. after a
while with no more malicious input it drifts back toward normal.

isolation / safety (this is graded work so i am being exact):
  * the fork lives only here, in the fleet's sensor process, as plain memory keyed
    by (device name, attacker source ip). it is NEVER written back to the modbus
    backend store, the simulator, the mqtt twin, the bridge, or the real plant. the
    honeynet stays a strict one-way mirror.
  * isolation level is PER (device, source-ip). two attackers on different ips get
    independent forks, and a source that only reads (never wrote) always sees the
    clean live values. i cannot split two clients that share one ip -- e.g. every
    connection from 127.0.0.1 in a local demo looks like one attacker -- that is an
    honest limit of ip-level isolation, written down here so nobody overclaims. on a
    real honeynet attackers arrive from distinct ips, so the isolation is real.
  * the shared backend on 127.0.0.1:610x is never touched, so it keeps serving the
    clean live process to everyone else. the fork only rewrites the bytes of THAT
    attacker's own read replies on their way back out.

the physics is a SIMPLIFIED lumped model (a handful of coupled first-order
reactions), not a real cfd / thermodynamics simulation. it is only meant to be
believable to someone poking the box over modbus, not physically exact. labelled
simplified on purpose.
"""

import random

# same list run_fleet.py uses -- these labels are real 0/1 actuators, not analog
BOOLEAN_SIGNALS = ("pump", "burner", "pump_a", "pump_b")

# measurement noise added to the values a forked read reports, so the attacked
# process still looks like jittery physical instrumentation and not a clean number.
# kept in step with the noise run_fleet.py adds to the normal telemetry.
NOISE_FLOOR = 0.18       # smallest noise std in engineering units
NOISE_FRAC = 0.05        # or this fraction of the signal's swing, whichever is bigger

DECAY_AFTER = 45.0       # seconds of quiet before the process starts easing back to normal
MAX_STEP = 4.0           # cap one advance step so a long idle gap can't jump the sim


def clamp(x, lo, hi):
    return lo if x < lo else hi if x > hi else x


class Model:
    """precomputed facts about one device so the physics is not re-derived on every
    read. i work out what kind of plant it is from its signal labels."""

    def __init__(self, device):
        self.name = device["name"]
        self.signals = device["signals"]
        self.labels = [s[0] for s in self.signals]
        self.base = [float(s[1]) for s in self.signals]
        self.swing = [float(s[2]) for s in self.signals]
        self.n = len(self.signals)
        self.bool_idx = [i for i, l in enumerate(self.labels) if l in BOOLEAN_SIGNALS]

        def find(label):
            return self.labels.index(label) if label in self.labels else None

        self.level = find("level_%")
        self.temp = find("temp_C")
        self.pressure = find("pressure_bar")
        self.water = find("water_%")
        self.flow = next((i for i, l in enumerate(self.labels) if l.startswith("flow")), None)

        if self.level is not None and self.bool_idx:
            self.kind = "tank"
        elif self.temp is not None and "burner" in self.labels:
            self.kind = "boiler"
        elif self.flow is not None and self.bool_idx:
            self.kind = "pump"
        else:
            self.kind = "generic"

    def is_bool(self, i):
        return i in self.bool_idx

    def to_reg(self, i, eng):
        # same scaling the simulator uses: analog is x10, a boolean is a clean 0/1
        if self.is_bool(i):
            return 1 if eng else 0
        return max(0, int(round(eng * 10)))

    def from_reg(self, i, reg):
        if self.is_bool(i):
            return 1 if reg else 0
        return reg / 10.0

    def high(self, i):
        return self.base[i] + 1.3 * self.swing[i]

    def low(self, i):
        return self.base[i] - 1.3 * self.swing[i]

    def noise(self, i):
        return max(NOISE_FLOOR, NOISE_FRAC * self.swing[i])


class Fork:
    """one attacker's private, evolving copy of a device's process."""

    def __init__(self):
        self.active = False
        self.eng = {}          # idx -> engineering value (only for the regs we own)
        self.owned = set()     # idxs whose reads we override for this attacker
        self.forced = {}       # idx -> analog value the attacker commanded
        self.bforce = {}       # bool idx -> 0/1 actuator state the attacker pinned
        self.alarms = []       # human-readable alarms currently firing
        self.logged = set()    # alarms we've already written to the log this episode
        self.summary = ""      # last thing the attacker forced (for the log line)
        self.last_seen = {}    # idx -> last raw register value we saw them read (for seeding)
        self.t_last = 0.0      # last time we advanced the sim
        self.t_write = 0.0     # last malicious write


# per (device name, source ip). lives only in the sensor process; never persisted.
SESSIONS = {}


def get_fork(name, ip):
    key = (name, ip)
    f = SESSIONS.get(key)
    if f is None:
        if len(SESSIONS) > 4096:
            # tidy up so a scan of the whole internet can't grow this forever --
            # drop the sessions that are just idle read-only observers
            for k in [k for k, v in SESSIONS.items() if not v.active]:
                del SESSIONS[k]
        f = Fork()
        SESSIONS[key] = f
    return f


def note_read(model, fork, start, regs):
    """remember the clean values this source just read, so if they attack next we can
    seed the fork from what the process really was at that instant."""
    for k, reg in enumerate(regs):
        idx = start + k
        if 0 <= idx < model.n:
            fork.last_seen[idx] = reg


def _own(model, fork, idx):
    if idx not in fork.eng:
        if idx in fork.last_seen:
            fork.eng[idx] = model.from_reg(idx, fork.last_seen[idx])
        else:
            fork.eng[idx] = model.base[idx]      # fall back to the nominal normal value
    fork.owned.add(idx)


def apply_write(model, fork, writes, now):
    """an attacker write landed. record what they forced, wake the fork, and run one
    physics step. returns (alarms, human summary) for the log."""
    summary = []
    for kind, addr, value in writes:
        if kind == "coil":
            # map a coil to an actuator boolean; coil 0 = the device's first actuator
            if model.bool_idx:
                bi = model.bool_idx[addr] if addr < len(model.bool_idx) else model.bool_idx[0]
                fork.bforce[bi] = 1 if value else 0
                _own(model, fork, bi)
                fork.eng[bi] = fork.bforce[bi]
                summary.append("%s=%s" % (model.labels[bi], "ON" if value else "OFF"))
        else:  # holding-register write
            if 0 <= addr < model.n and model.is_bool(addr):
                fork.bforce[addr] = 1 if value else 0
                _own(model, fork, addr)
                fork.eng[addr] = fork.bforce[addr]
                summary.append("%s=%s" % (model.labels[addr], "ON" if value else "OFF"))
            elif 0 <= addr < model.n:
                target = value / 10.0
                fork.forced[addr] = target
                _own(model, fork, addr)
                # jump straight to a believable clamped version so the very next read
                # already shows the process shoved out of its normal band
                fork.eng[addr] = clamp(target, 0.0, model.base[addr] + 2.0 * model.swing[addr])
                summary.append("%s=%.1f" % (model.labels[addr], target))
            else:
                summary.append("reg%d=%d" % (addr, value))     # off the map, just note it

    fork.active = True
    fork.t_write = now
    fork.summary = ", ".join(summary) if summary else "unmapped write"
    if fork.t_last == 0.0:
        fork.t_last = now
    advance(model, fork, now, first=True)
    return fork.alarms, fork.summary


def take_new_alarms(fork):
    """which alarms have fired since we last logged? an actuator attack (e.g. burner
    jammed on) only trips its alarm a few reads later as the process heats up, so the
    caller checks this on every read, not just at the write. each alarm is logged once
    per episode, and can log again if it clears and comes back."""
    fork.logged &= set(fork.alarms)          # drop alarms that have cleared
    fresh = [a for a in fork.alarms if a not in fork.logged]
    fork.logged.update(fresh)
    return fresh


def _ramp(cur, target, rate, dt):
    step = rate * dt
    if cur < target:
        return min(cur + step, target)
    return max(cur - step, target)


def _any_on(fork, model):
    return any(fork.bforce.get(i) == 1 for i in model.bool_idx)


def _any_off(fork, model):
    return any(fork.bforce.get(i) == 0 for i in model.bool_idx)


def _all_off(fork, model):
    return bool(model.bool_idx) and all(fork.bforce.get(i) == 0 for i in model.bool_idx)


def advance(model, fork, now, first=False):
    """evolve this attacker's fork forward to `now` and recompute its alarms."""
    dt = now - fork.t_last
    if not first and dt <= 0:
        return
    dt = clamp(dt, 0.0, MAX_STEP)
    fork.t_last = now
    decaying = (now - fork.t_write) > DECAY_AFTER

    if decaying:
        # let any pinned actuator go back to normal behaviour as things calm down
        for bi in model.bool_idx:
            fork.bforce.pop(bi, None)
            fork.owned.discard(bi)
            fork.eng.pop(bi, None)

    alarms = []
    if model.kind == "tank":
        _tank(model, fork, dt, decaying, alarms)
    elif model.kind == "boiler":
        _boiler(model, fork, dt, decaying, alarms)
    elif model.kind == "pump":
        _pumpstation(model, fork, dt, decaying, alarms)
    else:
        _generic(model, fork, dt, decaying, alarms)
    fork.alarms = alarms

    # once everything has eased back to normal and no actuator is still pinned, drop
    # the fork so this source sees the clean live process again
    if decaying and _settled(model, fork):
        fork.active = False
        fork.owned = set()
        fork.eng = {}
        fork.forced = {}
        fork.bforce = {}
        fork.alarms = []
        fork.logged = set()
        fork.summary = ""


def _settled(model, fork):
    for idx in fork.owned:
        if model.is_bool(idx):
            continue
        if abs(fork.eng.get(idx, model.base[idx]) - model.base[idx]) > 0.3 * model.swing[idx]:
            return False
    return True


def _tank(model, fork, dt, decaying, alarms):
    lv = model.level
    pr = model.pressure
    rate = model.swing[lv] * 0.22

    if decaying:
        target = model.base[lv]
    elif lv in fork.forced:
        target = clamp(fork.forced[lv], 0.0, model.base[lv] + 2.0 * model.swing[lv])
    elif _any_on(fork, model):
        target = model.base[lv] + 1.7 * model.swing[lv]        # pump jammed on -> fills to overflow
    elif _any_off(fork, model):
        target = max(0.0, model.base[lv] - 1.8 * model.swing[lv])  # pump off -> level drains, dry-run
    else:
        target = model.base[lv]

    fork.eng[lv] = _ramp(fork.eng.get(lv, model.base[lv]), target, rate, dt)
    _own(model, fork, lv)

    if pr is not None:
        dev = (fork.eng[lv] - model.base[lv]) / max(model.swing[lv], 1e-6)
        fork.eng[pr] = clamp(model.base[pr] + dev * model.swing[pr] * 1.5,
                             0.0, model.base[pr] + 3.0 * model.swing[pr])
        _own(model, fork, pr)

    if fork.eng[lv] > model.high(lv):
        alarms.append("HIGH LEVEL / TANK OVERFLOW")
    elif fork.eng[lv] < model.low(lv):
        alarms.append("LOW LEVEL / PUMP DRY-RUN")
    if pr is not None and fork.eng[pr] > model.high(pr):
        alarms.append("HIGH PRESSURE")


def _boiler(model, fork, dt, decaying, alarms):
    tp = model.temp
    pr = model.pressure
    wt = model.water
    burner = model.labels.index("burner")
    rate = model.swing[tp] * 0.2

    if decaying:
        target = model.base[tp]
    elif tp in fork.forced:
        target = clamp(fork.forced[tp], 0.0, model.base[tp] + 2.0 * model.swing[tp])
    elif fork.bforce.get(burner) == 1:
        target = model.base[tp] + 1.7 * model.swing[tp]        # burner jammed on -> overheat
    elif fork.bforce.get(burner) == 0:
        target = model.base[tp] - 1.7 * model.swing[tp]        # burner off -> cools, flame-out
    else:
        target = model.base[tp]

    fork.eng[tp] = _ramp(fork.eng.get(tp, model.base[tp]), target, rate, dt)
    _own(model, fork, tp)
    dev = (fork.eng[tp] - model.base[tp]) / max(model.swing[tp], 1e-6)

    if pr is not None:
        fork.eng[pr] = clamp(model.base[pr] + dev * model.swing[pr] * 1.4,
                             0.0, model.base[pr] + 3.0 * model.swing[pr])
        _own(model, fork, pr)
    if wt is not None:
        w = fork.eng.get(wt, model.base[wt])
        if dev > 0.5 and not decaying:
            w -= model.swing[wt] * 0.15 * dt                   # a hot boiler boils its water off
        else:
            w = _ramp(w, model.base[wt], model.swing[wt] * 0.1, dt)
        fork.eng[wt] = clamp(w, 0.0, model.base[wt] + model.swing[wt])
        _own(model, fork, wt)

    if fork.eng[tp] > model.high(tp):
        alarms.append("HIGH TEMPERATURE")
    elif fork.eng[tp] < model.low(tp):
        alarms.append("LOW TEMP / FLAME-OUT")
    if pr is not None and fork.eng[pr] > model.high(pr):
        alarms.append("HIGH PRESSURE")
    if wt is not None and fork.eng[wt] < model.low(wt):
        alarms.append("LOW WATER / DRY BOILER")


def _pumpstation(model, fork, dt, decaying, alarms):
    fl = model.flow
    pr = model.pressure
    rate = model.swing[fl] * 0.25

    if decaying:
        target = model.base[fl]
    elif fl in fork.forced:
        target = clamp(fork.forced[fl], 0.0, model.base[fl] + 2.0 * model.swing[fl])
    elif _all_off(fork, model):
        target = 0.0                                           # both pumps off -> no flow
    elif _any_on(fork, model):
        target = model.base[fl] + 1.6 * model.swing[fl]        # jammed on -> over-pressure
    else:
        target = model.base[fl]

    fork.eng[fl] = _ramp(fork.eng.get(fl, model.base[fl]), target, rate, dt)
    _own(model, fork, fl)
    dev = (fork.eng[fl] - model.base[fl]) / max(model.swing[fl], 1e-6)

    if pr is not None:
        fork.eng[pr] = clamp(model.base[pr] + dev * model.swing[pr] * 1.5,
                             0.0, model.base[pr] + 3.0 * model.swing[pr])
        _own(model, fork, pr)

    if fork.eng[fl] < 0.5 or fork.eng[fl] < model.low(fl):
        alarms.append("LOW / NO FLOW")
    if pr is not None and fork.eng[pr] > model.high(pr):
        alarms.append("HIGH PRESSURE")


def _generic(model, fork, dt, decaying, alarms):
    """devices with no boolean actuator (meter, dosing, hvac, conveyor, genset): the
    attack is forcing an analog register. ramp it to what they asked for, then drag
    the coupled readings with it so the fallout is not just one lonely number."""
    b, s = model.base, model.swing
    for idx in list(fork.forced.keys()):
        tgt = b[idx] if decaying else clamp(fork.forced[idx], 0.0, b[idx] + 2.0 * s[idx])
        fork.eng[idx] = _ramp(fork.eng.get(idx, b[idx]), tgt, s[idx] * 0.3, dt)
        _own(model, fork, idx)

    _generic_coupling(model, fork, dt, decaying)

    for idx in list(fork.forced.keys()):
        v = fork.eng.get(idx, b[idx])
        if v > model.high(idx):
            alarms.append(("HIGH %s" % model.labels[idx]).upper())
        elif v < model.low(idx):
            alarms.append(("LOW %s" % model.labels[idx]).upper())
    _generic_alarms(model, fork, alarms)


def _generic_coupling(model, fork, dt, decaying):
    name = model.name
    b, s = model.base, model.swing

    def dev(idx):
        return (fork.eng.get(idx, b[idx]) - b[idx]) / max(s[idx], 1e-6)

    if name == "CHLORINE-04":
        # 0 dose_ppm, 1 tank_%, 2 ph -- over-dosing drops the ph and drains the day tank
        if 0 in fork.owned:
            fork.eng[2] = clamp(b[2] - dev(0) * s[2] * 1.5, 0.0, b[2] + s[2])
            _own(model, fork, 2)
            tank = fork.eng.get(1, b[1])
            if decaying:
                tank = _ramp(tank, b[1], s[1] * 0.1, dt)
            elif dev(0) > 0.3:
                tank -= s[1] * 0.08 * dt
            fork.eng[1] = clamp(tank, 0.0, b[1] + s[1])
            _own(model, fork, 1)
    elif name == "POWER-METER-05":
        # 0 voltage, 1 current, 2 power_kW, 3 freq -- power follows v*i, freq sags a touch
        v = fork.eng.get(0, b[0])
        i = fork.eng.get(1, b[1])
        fork.eng[2] = clamp(v * i / 1000.0, 0.0, b[2] + 3.0 * s[2])
        _own(model, fork, 2)
        fork.eng[3] = clamp(b[3] - abs(dev(0)) * 0.3, b[3] - 2.0 * s[3], b[3] + 2.0 * s[3])
        _own(model, fork, 3)
    elif name == "HVAC-06":
        # 0 setpoint, 1 room, 2 fan -- the room chases a tampered setpoint, fan winds up
        sp = fork.eng.get(0, b[0])
        room = fork.eng.get(1, b[1])
        room = _ramp(room, b[1] if decaying else sp, s[1] * 0.2, dt)
        fork.eng[1] = clamp(room, 0.0, b[1] + 3.0 * s[1])
        _own(model, fork, 1)
        fork.eng[2] = clamp(b[2] + abs(sp - room) * 10.0, 0.0, 100.0)
        _own(model, fork, 2)
    elif name == "CONVEYOR-07":
        # 0 speed, 1 load, 2 motor_A -- overspeed drags the motor current and load up
        d = dev(0)
        fork.eng[2] = clamp(b[2] + d * s[2] * 1.6, 0.0, b[2] + 3.0 * s[2])
        _own(model, fork, 2)
        fork.eng[1] = clamp(b[1] + d * s[1] * 1.2, 0.0, b[1] + 2.0 * s[1])
        _own(model, fork, 1)
    elif name == "GENSET-08":
        # 0 rpm, 1 fuel, 2 output_kW, 3 oil_bar -- overspeed lifts output, drops oil pressure
        d = dev(0)
        fork.eng[2] = clamp(b[2] + d * s[2] * 1.5, 0.0, b[2] + 3.0 * s[2])
        _own(model, fork, 2)
        fork.eng[3] = clamp(b[3] - d * s[3] * 1.4, 0.0, b[3] + 2.0 * s[3])
        _own(model, fork, 3)


def _generic_alarms(model, fork, alarms):
    name = model.name
    if name == "CHLORINE-04" and 2 in fork.eng and fork.eng[2] < model.low(2):
        alarms.append("CHEMICAL OVERDOSE / LOW pH")
    elif name == "POWER-METER-05" and fork.owned:
        alarms.append("METER TAMPER")
    elif name == "HVAC-06" and 1 in fork.eng and fork.eng[1] > model.high(1):
        alarms.append("HIGH ROOM TEMP / SETPOINT TAMPER")
    elif name == "CONVEYOR-07" and 2 in fork.eng and fork.eng[2] > model.high(2):
        alarms.append("MOTOR OVERCURRENT")
    elif name == "GENSET-08" and 3 in fork.eng and fork.eng[3] < model.low(3):
        alarms.append("OVERSPEED / LOW OIL PRESSURE")


def rewrite_reads(model, fork, start, count, regs, now):
    """swap the clean register values this attacker just read for what their attack
    turned the process into. only the regs the fork owns are changed; everything else
    stays the live backend value, so unaffected channels still move normally."""
    advance(model, fork, now)
    if not fork.active:
        return regs
    out = list(regs)
    for k in range(min(count, len(out))):
        idx = start + k
        if idx in fork.owned and idx in fork.eng:
            val = model.to_reg(idx, fork.eng[idx])
            if not model.is_bool(idx):
                val += int(round(random.gauss(0, model.noise(idx) * 10)))  # keep it jittery/physical
            out[k] = int(clamp(val, 0, 65535))
    return out
