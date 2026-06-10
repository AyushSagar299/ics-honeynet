from flask import Flask, jsonify
from pymodbus.client import ModbusTcpClient

app = Flask(__name__)

@app.route('/')
def index():
    return '<h1>ICS HMI</h1><p>System: Online</p>'

@app.route('/status')
def status():
    client = ModbusTcpClient('10.10.0.10', port=502)
    client.connect()
    result = client.read_holding_registers(0, 5)
    client.close()
    return jsonify({'registers': result.registers})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
