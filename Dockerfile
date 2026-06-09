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
# Vendored scanner configs — copied at build time so scans never hit external networks.
COPY semgrep_configs/ ./semgrep_configs/
COPY eslint_security/ ./eslint_security/

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir ".[providers,scanners]"

# --- Runtime stage -------------------------------------------------------------
FROM python:3.12-slim AS runtime

# curl is needed for the HEALTHCHECK probe below.
# nodejs + npm are needed for the ESLint-security scanner adapter.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl nodejs npm \
 && rm -rf /var/lib/apt/lists/*

# Install ESLint and eslint-plugin-security at pinned versions.
# These must match the versions in eslint_security/.eslintrc.security.json.
RUN npm install -g eslint@8.57.1 eslint-plugin-security@3.0.0 eslint-plugin-no-unsanitized@4.1.5 \
 && npm cache clean --force

# Install gosec (Go security checker) from a pinned GitHub release.
# SHA-256 sourced from gosec_2.27.1_checksums.txt on the official GitHub Releases page.
RUN set -eux; \
    GOSEC_VERSION="2.27.1"; \
    GOSEC_URL="https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz"; \
    curl -fsSL "${GOSEC_URL}" -o /tmp/gosec.tar.gz; \
    echo "a1cc5fba45fb51131ba05dee4029b364f62f4b6739b8f24236f93de82f40da40  /tmp/gosec.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gosec.tar.gz -C /tmp gosec; \
    mv /tmp/gosec /usr/local/bin/gosec; \
    chmod +x /usr/local/bin/gosec; \
    rm /tmp/gosec.tar.gz

# Non-root user, no login shell, fixed uid for K8s PSP compatibility.
RUN groupadd --gid 1000 app \
 && useradd --uid 1000 --gid 1000 --home /home/app --create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv
# Alembic config + migration scripts are needed by the lifespan hook when
# RUN_MIGRATIONS_ON_STARTUP=true. Place them at the runtime WORKDIR so the
# relative path in alembic.ini (``script_location = alembic``) resolves.
COPY --from=builder --chown=1000:1000 /build/alembic /home/app/alembic
COPY --from=builder --chown=1000:1000 /build/alembic.ini /home/app/alembic.ini
# Vendored scanner configs — adapters resolve these via Path(__file__).parents[5]
# which lands at /opt/venv/lib/python3.12/. Copy them there so semgrep + eslint
# adapters can find their pinned rulesets without network egress.
COPY --from=builder /build/semgrep_configs /opt/venv/lib/python3.12/semgrep_configs
COPY --from=builder /build/eslint_security /opt/venv/lib/python3.12/eslint_security

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