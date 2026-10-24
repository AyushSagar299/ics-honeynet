three repeats of the fidelity run, 15 October 2026

each file is one 40 s run of analysis/collect_data.py with the full pipeline up
(tank_plc.py on 5020, bridge, twin, live decoy on 5021), one row every ~0.5 s:
t, real_level, decoy_level, real_temp, decoy_temp

mean absolute level error (percentage points of tank level):
  run 1  0.019   (3 of 79 samples differ)
  run 2  0.115   (13 of 79)
  run 3  0.106   (16 of 79)
mean of the three: 0.080. best lag 0 s in all three.
analysis/fidelity.csv is the original run (0.113).
