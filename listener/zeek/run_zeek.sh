#!/usr/bin/env bash
#
# run_zeek.sh -- turn a capture file into Zeek protocol logs.
#
# Zeek understands Modbus out of the box, so it writes a modbus.log (every
# request/response) and a conn.log (every connection). We ask for JSON output
# because that is the deliverable and it is easy to load later with pandas.
#
# usage:
#   ./run_zeek.sh                       # uses the sample capture
#   ./run_zeek.sh /path/to/capture.pcap # uses your own capture

set -e
cd "$(dirname "$0")"                     # always work from the listener/zeek/ folder

PCAP="${1:-../scapy/sample_modbus.pcap}"
# turn the path into an absolute one so it still works after we change folder
PCAP="$(cd "$(dirname "$PCAP")" && pwd)/$(basename "$PCAP")"

mkdir -p logs
cd logs
rm -f ./*.log

# LogAscii::use_json=T makes Zeek write the logs as JSON lines
zeek -r "$PCAP" LogAscii::use_json=T

echo "Zeek logs written to listener/zeek/logs/:"
ls -1 ./*.log
