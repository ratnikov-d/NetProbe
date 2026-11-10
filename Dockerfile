FROM python:3.11-slim

ENV TZ=Europe/Moscow
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask flask-login flask-wtf requests

COPY app.py .
COPY templates/ templates/
COPY static/ static/

ENV DB_NAME=/app/data/port_scanner.db
RUN mkdir -p /app/data
VOLUME /app/data

EXPOSE 5000

CMD ["python", "app.py"]
