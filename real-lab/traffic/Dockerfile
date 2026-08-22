FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
RUN pip install pymodbus==3.6.9 asyncua==2.0.1 requests==2.32.3
COPY generator.py /app/generator.py
WORKDIR /app
CMD ["python", "generator.py"]
