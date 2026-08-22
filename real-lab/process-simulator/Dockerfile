FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
RUN pip install pymodbus==3.6.9
COPY tank_plc.py /app/tank_plc.py
WORKDIR /app
# inside Docker we can use the real Modbus port (no sudo needed like on the Mac)
ENV MODBUS_PORT=502
CMD ["python", "tank_plc.py"]
