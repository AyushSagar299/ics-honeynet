"""
devices.py -- the honeypot fleet.

Each entry is one fake industrial device. They all speak Modbus, but pretend to
be different machines from different vendors, so an attacker scanning the
honeynet finds a whole plant of real-looking equipment, not one lonely PLC.

For each device:
  name      -- what it pretends to be
  kind      -- a human description (shown on the dashboard)
  public    -- the port an attacker connects to (the sensor listens here)
  internal  -- the port the real decoy backend listens on (127.0.0.1 only)
  id        -- the device identity it reports over Modbus (fn 43): a REAL vendor /
               product / model / firmware, so "who are you?" gets a believable
               answer and every device looks different (not a clone)
  signals   -- the registers it serves. Each signal is a slow wave so the value
               looks alive: (label, base, swing, period_seconds).
"""

DEVICES = [
    {"name": "WATER-TANK-01", "kind": "Water tank PLC", "public": 5101, "internal": 6101,
     "id": {"vendor": "Schneider Electric", "product": "BMXP342020", "model": "Modicon M340", "version": "2.70"},
     "signals": [("level_%", 60, 25, 90), ("temp_C", 23, 4, 140), ("pressure_bar", 6, 2, 90), ("pump", 1, 1, 60)]},

    {"name": "BOILER-02", "kind": "Steam boiler controller", "public": 5102, "internal": 6102,
     "id": {"vendor": "WAGO", "product": "750-8210", "model": "PFC200 CS", "version": "03.10.10"},
     "signals": [("temp_C", 180, 20, 160), ("pressure_bar", 12, 3, 110), ("burner", 1, 1, 70), ("water_%", 55, 15, 130)]},

    {"name": "PUMP-STATION-03", "kind": "Water pump station", "public": 5103, "internal": 6103,
     "id": {"vendor": "Schneider Electric", "product": "TM221CE24R", "model": "Modicon M221", "version": "1.6"},
     "signals": [("flow_lps", 40, 12, 100), ("pressure_bar", 5, 1.5, 80), ("pump_a", 1, 1, 55), ("pump_b", 1, 1, 75)]},

    {"name": "CHLORINE-04", "kind": "Chlorine dosing unit", "public": 5104, "internal": 6104,
     "id": {"vendor": "Siemens", "product": "6ES7215-1AG40", "model": "SIMATIC S7-1200", "version": "4.4"},
     "signals": [("dose_ppm", 1.2, 0.4, 120), ("tank_%", 70, 20, 200), ("ph", 7.1, 0.3, 150)]},

    {"name": "POWER-METER-05", "kind": "Substation power meter", "public": 5105, "internal": 6105,
     "id": {"vendor": "Schneider Electric", "product": "METSEPM8244", "model": "PowerLogic PM8000", "version": "2.1"},
     "signals": [("voltage_V", 230, 6, 40), ("current_A", 45, 15, 65), ("power_kW", 10, 4, 65), ("freq_Hz", 50, 0.2, 30)]},

    {"name": "HVAC-06", "kind": "Building HVAC controller", "public": 5106, "internal": 6106,
     "id": {"vendor": "Honeywell", "product": "PVL6438NS", "model": "Spyder BACnet/Modbus", "version": "3.2"},
     "signals": [("setpoint_C", 21, 1, 300), ("room_C", 21, 2, 180), ("fan_%", 60, 30, 120)]},

    {"name": "CONVEYOR-07", "kind": "Conveyor line drive", "public": 5107, "internal": 6107,
     "id": {"vendor": "Rockwell Automation", "product": "1766-L32BWA", "model": "Allen-Bradley MicroLogix 1400", "version": "21.0"},
     "signals": [("speed_mps", 1.5, 0.3, 90), ("load_%", 55, 25, 110), ("motor_A", 30, 8, 70)]},

    {"name": "GENSET-08", "kind": "Backup diesel generator", "public": 5108, "internal": 6108,
     "id": {"vendor": "Deep Sea Electronics", "product": "DSE8610", "model": "DSE8610 MKII", "version": "7.1"},
     "signals": [("rpm", 1500, 40, 50), ("fuel_%", 80, 5, 400), ("output_kW", 120, 30, 80), ("oil_bar", 4, 0.5, 60)]},
]
