FROM python:3.11-slim AS api

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY sentinel ./sentinel
COPY web ./web
COPY results ./results
RUN pip install --no-cache-dir .
ENV SENTINEL_ROOT=/app

RUN useradd --create-home appuser && mkdir -p /data && chown appuser /data
USER appuser

EXPOSE 8000
CMD ["uvicorn", "sentinel.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Scanner image: Opengrep (pinned release binary) + Bandit. Scans mounted code
# read-only; nothing scanned is ever executed.
FROM python:3.11-slim AS scanner

ARG OPENGREP_VERSION=v1.31.0
ARG OPENGREP_SHA256=dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL -o /usr/local/bin/opengrep \
       "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86" \
    && echo "${OPENGREP_SHA256}  /usr/local/bin/opengrep" | sha256sum -c - \
    && chmod +x /usr/local/bin/opengrep \
    && apt-get purge -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentinel ./sentinel
RUN pip install --no-cache-dir ".[scan-bandit]"

RUN useradd --create-home appuser
USER appuser
ENTRYPOINT ["python", "-m", "sentinel.scanners.cli"]
