FROM python:3.11-slim
RUN pip install asyncua
COPY server.py /app/server.py
WORKDIR /app
CMD ["python", "server.py"]
