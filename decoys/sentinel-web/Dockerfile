FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY pyproject.toml ./
COPY app/ ./app/

RUN pip install --no-cache-dir .

# Runs as nobody (65534) via compose `user:`. The container is read_only;
# the only writable path is the mounted /logs volume.
EXPOSE 8080

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--no-server-header", "--access-log"]
