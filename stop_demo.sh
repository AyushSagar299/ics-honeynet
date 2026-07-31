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
echo "demo stopped."
