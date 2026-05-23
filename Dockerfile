# syntax=docker/dockerfile:1.7

# --- Builder stage -------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src/ ./src/
# Alembic migrations are runtime artefacts (executed at startup when
# RUN_MIGRATIONS_ON_STARTUP=true) — bake them in alongside the source tree.
COPY alembic/ ./alembic/
COPY alembic.ini ./

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir ".[providers]"

# --- Runtime stage -------------------------------------------------------------
FROM python:3.12-slim AS runtime

# curl is needed for the HEALTHCHECK probe below. Nothing else from the
# apt cache is kept.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root user, no login shell, fixed uid for K8s PSP compatibility.
RUN groupadd --gid 1000 app \
 && useradd --uid 1000 --gid 1000 --home /home/app --create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv
# Alembic config + migration scripts are needed by the lifespan hook when
# RUN_MIGRATIONS_ON_STARTUP=true. Place them at the runtime WORKDIR so the
# relative path in alembic.ini (``script_location = alembic``) resolves.
COPY --from=builder --chown=1000:1000 /build/alembic /home/app/alembic
COPY --from=builder --chown=1000:1000 /build/alembic.ini /home/app/alembic.ini

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

USER 1000:1000
WORKDIR /home/app

# Read-only root filesystem is enforced by the platform via Kubernetes
# securityContext (readOnlyRootFilesystem: true). The service is stateless
# and never writes to local disk during normal request handling — no
# emptyDir/tmpfs mounts are required for production. The Helm chart should
# still declare them empty for explicitness.

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS "http://localhost:${PORT:-8000}/healthz" || exit 1

CMD ["sh", "-c", "uvicorn security_scanner.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
