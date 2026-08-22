FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
# same pins as the project requirements.txt, so laptop and Docker behave the same
RUN pip install asyncua==2.0.1 pymodbus==3.6.9
COPY server.py /app/server.py
WORKDIR /app
CMD ["python", "server.py"]
