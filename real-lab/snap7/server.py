import snap7
from snap7.server import Server
import time

server = Server()
size = 100
DB1 = (snap7.types.wordlen_to_ctypes[0x04] * size)()
server.register_area(snap7.types.srvAreaDB, 1, DB1)
server.start(tcpport=102)
print('S7 simulator running on port 102')

# Keep running
while True:
    time.sleep(1)
