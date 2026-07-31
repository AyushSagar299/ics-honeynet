#!/bin/bash
# demo.sh - start the ICS honeynet demo on macOS.
# Run it with:  ./demo.sh
# Stop it with: ./stop_demo.sh
# job control on, so each thing we start below gets its own process group
# and stop_demo.sh can kill it together with its children
set -m
cd "$(dirname "$0")" || exit 1
PY="$PWD/.venv/bin/python"
PIDFILE=/tmp/honeynet_pids.txt

if [ ! -x "$PY" ]; then
  echo "ERROR: virtual environment not found. Run the setup first."
  exit 1
fi

# make sure an old run is not still holding the ports
./stop_demo.sh >/dev/null 2>&1
sleep 1

# start each run with a clean log
: > honeynet/fleet/connections.log
: > honeynet/fleet/actions.log

echo "starting the honeypot fleet (8 fake devices) ..."
( cd honeynet/fleet && exec "$PY" run_fleet.py ) >/tmp/honeynet_fleet.log 2>&1 &
FLEET=$!

echo "starting the static honeypot on port 5022 (for the comparison) ..."
"$PY" honeynet/modbus-decoy/static_decoy.py >/tmp/honeynet_static.log 2>&1 &
STATIC=$!

echo "starting the threat dashboard ..."
( cd honeynet/fleet && exec "$PY" dashboard.py ) >/tmp/honeynet_dash.log 2>&1 &
DASH=$!

# remember what we started so stop_demo.sh can stop exactly these
printf '%s\n' "$FLEET" "$STATIC" "$DASH" > "$PIDFILE"

sleep 6
# put some example worldwide attacker IPs on the map so it is not empty
echo "adding example worldwide attacker IPs to the map ..."
( cd honeynet/fleet && "$PY" demo_attackers.py 12 ) >/dev/null 2>&1

echo ""
grep -q "fleet up" /tmp/honeynet_fleet.log && echo "  [ok] fleet up on ports 5101-5108" || echo "  [!!] fleet did not start -- see /tmp/honeynet_fleet.log"
grep -q "STATIC"   /tmp/honeynet_static.log && echo "  [ok] static honeypot up on port 5022" || echo "  [!!] static honeypot problem -- see /tmp/honeynet_static.log"
# ask for the status code instead of just printing it, otherwise a refused
# connection still looks like an [ok]
code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8100/)
[ "$code" = "200" ] && echo "  [ok] dashboard up -> HTTP $code" || echo "  [!!] dashboard did not start -- see /tmp/honeynet_dash.log"

echo ""
echo "READY.  Dashboard: http://localhost:8100"
echo "Stop everything with:  ./stop_demo.sh"
open http://localhost:8100 2>/dev/null
