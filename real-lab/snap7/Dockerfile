FROM python:3.11-slim
RUN pip install python-snap7
COPY server.py /app/server.py
WORKDIR /app
CMD ["python", "server.py"]
