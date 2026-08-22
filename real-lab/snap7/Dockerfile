FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
# python-snap7 3.x ships a pure-Python S7 server, so no native snap7 library is needed
RUN pip install python-snap7==3.1.2 pymodbus==3.6.9
COPY server.py /app/server.py
WORKDIR /app
CMD ["python", "server.py"]
