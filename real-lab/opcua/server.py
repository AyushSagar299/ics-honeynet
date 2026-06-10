import asyncio
from asyncua import Server

async def main():
    server = Server()
    await server.init()
    server.set_endpoint('opc.tcp://0.0.0.0:4840/freeopcua/server/')
    uri = 'http://ics-lab.local'
    idx = await server.register_namespace(uri)
    obj = await server.nodes.objects.add_object(idx, 'PLC1')
    temp = await obj.add_variable(idx, 'Temperature', 23.4)
    pressure = await obj.add_variable(idx, 'Pressure', 101.3)
    await temp.set_writable()
    await pressure.set_writable()
    print('OPC UA server running on port 4840')
    async with server:
        while True:
            await asyncio.sleep(1)

asyncio.run(main())
