FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

COPY . /app
RUN mkdir -p /app/logs /app/flask_session

EXPOSE 8000

ENV GUNICORN_WORKERS=4 \
    GUNICORN_BIND=0.0.0.0:8000 \
    GUNICORN_TIMEOUT=120 \
    GUNICORN_LOG_DIR=/app/logs

CMD ["sh", "-c", "gunicorn --workers ${GUNICORN_WORKERS} --bind ${GUNICORN_BIND} --timeout ${GUNICORN_TIMEOUT} --access-logfile ${GUNICORN_LOG_DIR}/access.log --error-logfile ${GUNICORN_LOG_DIR}/error.log fuco:app"]
