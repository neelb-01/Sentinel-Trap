FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Non-root: this process only ever reads the log volume and talks to Redis/Postgres.
RUN useradd --system --uid 10001 sentinel
USER sentinel

CMD ["python", "-m", "sentinel_pipeline.tailer"]
