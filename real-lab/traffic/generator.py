import time, asyncio, requests
from pymodbus.client import ModbusTcpClient
from asyncua import Client

def poll_modbus():
    c = ModbusTcpClient('10.10.0.10', port=502)
    c.connect()
    r = c.read_holding_registers(0, 10)
    print(f'[Modbus] registers: {r.registers}')
    c.close()

async def poll_opcua():
    async with Client('opc.tcp://10.10.0.12:4840') as c:
        node = c.get_node('ns=2;i=2')
        val = await node.read_value()
        print(f'[OPC UA] value: {val}')

def poll_hmi():
    r = requests.get('http://10.10.0.13:5000/status', timeout=3)
    print(f'[HMI] status: {r.status_code}')

print('Background traffic generator started')
while True:
    try:
        poll_modbus()
        asyncio.run(poll_opcua())
        poll_hmi()
    except Exception as e:
        print(f'Error: {e}')
    time.sleep(5)
