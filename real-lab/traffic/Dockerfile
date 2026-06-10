FROM python:3.11-slim
RUN pip install pymodbus asyncua requests
COPY generator.py /app/generator.py
WORKDIR /app
CMD ["python", "generator.py"]
