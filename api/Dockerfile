FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Talks only to Redis and Postgres on the platform network; never touches a
# decoy or the log volume, so no writable paths are needed.
RUN useradd --system --uid 10002 sentinel
USER sentinel

EXPOSE 8000

CMD ["uvicorn", "sentinel_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
