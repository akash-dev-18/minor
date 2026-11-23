FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup --system sentinel \
    && adduser --system --ingroup sentinel --no-create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /app/data/uploads /app/ml-artifacts \
    && chown -R sentinel:sentinel /app/data /app/ml-artifacts

COPY --chown=sentinel:sentinel alembic.ini ./
COPY --chown=sentinel:sentinel migrations ./migrations
COPY --chown=sentinel:sentinel app ./app

USER sentinel

ENV DATABASE_URL=sqlite+aiosqlite:////app/data/sentinel.db \
    UPLOAD_DIR=/app/data/uploads \
    ML_ARTIFACT_DIR=/app/ml-artifacts \
    APP_ENV=production \
    DEBUG=false

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8000/api/v1/ready || exit 1

STOPSIGNAL SIGTERM

CMD ["sh", "-c", "set -e; alembic upgrade head; exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
