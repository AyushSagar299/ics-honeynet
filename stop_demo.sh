#!/bin/bash
# stop_demo.sh - stop the ICS honeynet demo on macOS.
PIDFILE=/tmp/honeynet_pids.txt

if [ -f "$PIDFILE" ]; then
  while read -r pid; do
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    # the minus in front of the pid means "the whole process group", same idea as
    # taskkill /T on windows. without it the modbus backends that multiprocessing
    # spawns are left running and keep holding the internal ports.
    if kill -TERM -- "-$pid" 2>/dev/null; then
      echo "stopped $pid"
    fi
  done < "$PIDFILE"
  rm -f "$PIDFILE"
else
  echo "nothing to stop (no pid file)."
fi

# an OPC UA decoy started by hand (or left over from a crashed run) is not in the
# pid file, and it would keep sitting on port 4840 so the next demo.sh cannot bind
# it. i ask lsof who holds the port and only kill it if it really is our decoy --
# pgrep -f on its own also matches any shell that just mentions the script name.
for pid in $(lsof -nP -iTCP:4840 -sTCP:LISTEN -t 2>/dev/null); do
  if ps -o command= -p "$pid" 2>/dev/null | grep -q decoy_opcua.py; then
    kill -TERM "$pid" 2>/dev/null && echo "stopped leftover opcua decoy $pid"
  fi
done

echo "demo stopped."
