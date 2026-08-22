FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
RUN pip install Flask==3.0.3 pymodbus==3.6.9
COPY app.py /app/app.py
WORKDIR /app
CMD ["python", "app.py"]
