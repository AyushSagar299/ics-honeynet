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

# a laptop demo stays on this machine. on a real isolated deployment run it with
# FLEET_BIND=0.0.0.0 ./demo.sh so the decoys can be reached from the decoy network.
export FLEET_BIND="${FLEET_BIND:-127.0.0.1}"

# start each run with a clean log
: > honeynet/fleet/connections.log
: > honeynet/fleet/actions.log

echo "starting the honeypot fleet (8 fake devices) ..."
( cd honeynet/fleet && exec "$PY" run_fleet.py ) >/tmp/honeynet_fleet.log 2>&1 &
FLEET=$!

echo "starting the OPC UA decoy on port 4840 (the second protocol) ..."
"$PY" honeynet/opcua-decoy/decoy_opcua.py >/tmp/honeynet_opcua.log 2>&1 &
OPCUA=$!

echo "starting the static honeypot on port 5022 (for the comparison) ..."
"$PY" honeynet/modbus-decoy/static_decoy.py >/tmp/honeynet_static.log 2>&1 &
STATIC=$!

echo "starting the decoy HMI with the honeytoken files on port 8090 ..."
"$PY" honeynet/hmi/decoy_hmi.py >/tmp/honeynet_hmi.log 2>&1 &
HMI=$!

echo "starting the threat dashboard ..."
( cd honeynet/fleet && exec "$PY" dashboard.py ) >/tmp/honeynet_dash.log 2>&1 &
DASH=$!

# remember what we started so stop_demo.sh can stop exactly these
printf '%s\n' "$FLEET" "$OPCUA" "$STATIC" "$HMI" "$DASH" > "$PIDFILE"

sleep 6
# put some example worldwide attacker IPs on the map so it is not empty
echo "adding example worldwide attacker IPs to the map ..."
( cd honeynet/fleet && "$PY" demo_attackers.py 12 ) >/dev/null 2>&1

echo ""
grep -q "fleet up" /tmp/honeynet_fleet.log && echo "  [ok] fleet up on ports 5101-5108" || echo "  [!!] fleet did not start -- see /tmp/honeynet_fleet.log"
# the log line only means our own process got going, so check that something is
# really sitting on 4840 as well, otherwise an old decoy still holding the port
# would look like a good start
if grep -q "decoy up" /tmp/honeynet_opcua.log && lsof -nP -iTCP:4840 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "  [ok] OPC UA decoy up on port 4840"
else
  echo "  [!!] OPC UA decoy did not start -- see /tmp/honeynet_opcua.log"
fi
grep -q "STATIC"   /tmp/honeynet_static.log && echo "  [ok] static honeypot up on port 5022" || echo "  [!!] static honeypot problem -- see /tmp/honeynet_static.log"
hcode=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8090/robots.txt)
[ "$hcode" = "200" ] && echo "  [ok] decoy HMI + honeytokens up on port 8090" || echo "  [!!] decoy HMI did not start -- see /tmp/honeynet_hmi.log"
# ask for the status code instead of just printing it, otherwise a refused
# connection still looks like an [ok]
code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8100/)
[ "$code" = "200" ] && echo "  [ok] dashboard up -> HTTP $code" || echo "  [!!] dashboard did not start -- see /tmp/honeynet_dash.log"

echo ""
echo "READY.  Dashboard: http://localhost:8100   Decoy HMI: http://localhost:8090"
echo "Listening on $FLEET_BIND (set FLEET_BIND=0.0.0.0 to expose the decoys on an isolated network)"
echo "Stop everything with:  ./stop_demo.sh"
open http://localhost:8100 2>/dev/null
