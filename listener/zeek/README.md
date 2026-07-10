# Zeek — protocol logs from a capture

Zeek reads a capture file and writes structured logs. It understands Modbus
out of the box, so you get:
- `conn.log` — every TCP connection (who talked to who, for how long)
- `modbus.log` — every Modbus request and response (function code, registers)

We write them as **JSON** so they are easy to load later with pandas.

## Install Zeek (once)
```bash
brew install zeek
```

## Run it
```bash
./run_zeek.sh                        # uses the sample capture
./run_zeek.sh /path/to/your.pcap     # uses your own capture
```
Logs land in `listener/zeek/logs/`.

## Note about the port
Zeek assumes Modbus is on port **502** (the real port). The Stage A laptop test
uses port **5020**, which Zeek will not recognise on its own. For that case, add
the little helper script:
```bash
zeek -r capture_on_5020.pcap modbus-ports.zeek LogAscii::use_json=T
```
`modbus-ports.zeek` just tells Zeek to also treat 5020 as Modbus.

## What a modbus.log line looks like
```json
{"ts":1751850001.0,"id.orig_h":"10.10.0.20","id.resp_h":"10.10.0.10",
 "id.resp_p":502,"tid":1,"unit":1,"func":"READ_HOLDING_REGISTERS","pdu_type":"REQ"}
```
