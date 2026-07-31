# Conceptual framing

This note sorts out three things I had muddled: the detector was aimed at the wrong
attack surface, the "dual-use residual" mixed up two different quantities, and the
observability ceiling was a definition rather than a result. What follows goes into
the report directly.

## 1. Two detection layers, two attack surfaces

The system detects attacks at two separate layers, and they must not be confused.

Layer 1 - Interaction detection (the honeynet layer).
Any connection to a decoy is suspect, because no legitimate client should ever
talk to it. Each decoy records every network and protocol interaction an attacker
performs against it: port scans, register reads, unauthorised writes, malformed
frames, floods, login attempts. These interactions are mapped to MITRE ATT&CK for
ICS techniques. This layer is what catches an attacker who is probing the fake
PLC. The method here is rule-based, not machine learning.

Layer 2 - Process-anomaly detection (the shadow layer).
A learned residual model over the plant's process telemetry flags physically
abnormal behaviour: values that break the normal multivariate pattern of the
process. This catches manipulation of the physical process itself, and it is
evaluated on the SWaT benchmark. The method here is machine learning.

These two layers address different attack surfaces and do not overlap. The ML
model does not detect a protocol attack on the decoy, and the interaction layer
does not detect a subtle physical process manipulation. The contribution of this
project is the complete system that combines believable deception with both
detection layers, under a provable one-way safety guarantee. Stating this split
plainly removes the "the detector doesn't detect attacks on the honeypot" hole,
because the honeypot attacks are handled by Layer 1, by design.

## 2. Two monitors, not one "dual-use residual"

The earlier text claimed one model read two ways. That was wrong: the two
readings are different quantities, and they are kept separate here.

Monitor A - anomaly score:
    a(t) = || observed_process(t)  -  shadow_prediction(t) ||
This is a learned residual. It needs the trained model. A high value means the
physical process is behaving abnormally (a possible attack or fault on the plant).

Monitor B - fidelity / health:
    d(t) = || decoy_exposed(t)  -  shadow_state(t) ||
This is a plain difference between two live signals. It needs no model. It is
near zero when the decoy is faithfully copying the shadow. A high value means the
decoy has drifted from the shadow (a stale feed or a delivery fault), which would
make the decoy detectable to an attacker.

They are not the same signal, and the report no longer claims they are.

The honest, and still useful, result is a regime analysis. Under a plant attack the
two do not decouple in the naive sense: the
shadow keeps mirroring the plant faithfully, so fidelity stays high while the
anomaly score spikes. That is precisely the point. Each monitor isolates a
different failure mode:

| Condition                         | Monitor A (anomaly) | Monitor B (fidelity) |
|-----------------------------------|---------------------|----------------------|
| Normal operation                  | low                 | low (about 0)        |
| Attack or fault on the real plant | high                | low (shadow still faithful) |
| Shadow drift / stale feed         | low                 | high                 |
| Decoy desynchronised              | low                 | high                 |

So the two monitors together let an operator tell a genuine plant attack
(A high, B low) apart from a mere loss of decoy fidelity (A low, B high). This is
a defensible finding, and it replaces the muddy "one residual, two roles" claim.

So the question becomes: can an anomaly residual and a fidelity difference, used
together, distinguish a real attack on the process from a loss of decoy fidelity?

## 3. The observability ceiling is state inference, not a definition

"How much of the process is recoverable from passive capture" is trivial if it
means "the variables that appear in the packets." The non-trivial and measurable
question is state inference: given only the variables observable on the wire, how
well can the unobserved variables be reconstructed from them?

I measure this directly. The sensors are split into an observed set (assumed to
appear in the captured Modbus traffic) and a hidden set (not captured). A model is
trained on normal data to predict the hidden tags from the observed ones, and the
reconstruction quality (R-squared, normalised RMSE) per hidden tag is reported. A
hidden tag with high R-squared can be shadowed faithfully even though it is never
seen; a hidden tag with low R-squared marks the real limit. That spread is the
ceiling, and it bounds how faithful the shadow, and therefore the decoy, can be.

So the question becomes: how much of the unobserved plant state can be inferred from
the passively observed variables, and how does that inference ceiling bound decoy
fidelity and detection performance?

## Summary of the corrections
- The honeypot attacks and the process anomalies are two separate layers, not one.
- The anomaly score and the fidelity index are two different quantities, reported
  separately, with a regime table that survives the "they converge under attack"
  objection.
- The observability ceiling is reframed as a measured state-inference result.
