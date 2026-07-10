# modbus-ports.zeek
#
# The real lab uses the normal Modbus port 502, which Zeek already knows.
# But the Stage A test on the laptop uses port 5020 (because 502 needs sudo).
# This little script tells Zeek to also treat 5020 as Modbus, so it can parse
# the loopback test capture too.
#
# use it like this:
#   zeek -r capture_on_5020.pcap modbus-ports.zeek LogAscii::use_json=T

event zeek_init()
    {
    Analyzer::register_for_port(Analyzer::ANALYZER_MODBUS, 5020/tcp);
    }
