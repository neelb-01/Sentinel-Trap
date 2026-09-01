FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Non-root: this process only ever reads the log volume and talks to Redis/Postgres.
# /state is pre-created (and owned by sentinel) here so that when Compose mounts the
# tailer-state named volume over it, Docker seeds the volume with these permissions —
# otherwise a fresh named volume is root-owned and the tailer can't checkpoint its offset.
RUN useradd --system --uid 10001 sentinel && mkdir -p /state && chown sentinel:sentinel /state
USER sentinel

CMD ["python", "-m", "sentinel_pipeline.tailer"]
