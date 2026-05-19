## Phrase Platform

This service targets **Phrase Platform** — Kubernetes (Amazon EKS).
All deployments go through GitHub Actions → ECR → Helm → EKS. There is no direct
cluster access.

Platform configuration is in `.phrase-platform/` — platform skills read it automatically.

### Development Guidelines

Follow the **12-Factor App** methodology (https://12factor.net/):

- **Config in env vars** — never hardcode URLs, credentials, or environment-specific values.
  Use environment variables for all configuration. Secrets are managed via GitHub Actions
  secrets and injected as env vars at runtime.
- **Stateless processes** — the app must not rely on local filesystem state between requests.
  Use external backing services for persistence. The platform provides **RDS PostgreSQL**
  as a managed database — connect via `DATABASE_URL` env var (provisioned automatically,
  credentials stored in AWS Secrets Manager). For object/file storage, the platform provides
  **S3 buckets** — bucket names available as GitHub Actions repo variables (`S3_BUCKET_<KEY>`,
  e.g. `${{ vars.S3_BUCKET_UPLOADS }}`), passed to the app as env vars at deploy time.
  Local disk is ephemeral (`emptyDir` only).
- **Port binding** — export the HTTP service via a port (default to `PORT` env var or a
  sensible framework default). The container will receive traffic on this port.
- **Disposability** — support graceful shutdown (handle SIGTERM). Kubernetes will send
  SIGTERM before killing the pod. Fast startup improves scaling and deployments.
- **Logs as streams** — write logs to stdout/stderr, not to files. The platform collects
  them automatically.
- **Dev/prod parity** — use the same backing services locally as in production where possible.
  For database workloads, develop against PostgreSQL locally (e.g. via Docker Compose) to
  match the RDS PostgreSQL instance used in production. For object storage, use LocalStack
  or MinIO locally to match the S3 bucket used in production.
- **Health endpoints** — expose `/healthz` (liveness) and `/readyz` (readiness) endpoints.
  Kubernetes uses these to manage pod lifecycle.

### Container Requirements

- Run as a **non-root user** in the Dockerfile
- Prefer a **read-only root filesystem** where possible
- **Explicitly declare dependencies** — no implicit system packages
- Use **multi-stage builds** to keep images small
- Set `EXPOSE` for the service port in Dockerfile

### CI/CD Requirements

- **All GitHub Actions jobs must use the platform's self-hosted runners** — use
  `runs-on: {github.runner}` from `.phrase-platform/*.yaml`. Do NOT use `ubuntu-latest`
  or other GitHub-hosted runners — they cannot reach internal services (ECR, EKS).
- This applies to every job: build, deploy, test, lint, etc.

### Authentication & Authorization

**Internal apps only** — public-facing apps are not supported.

- Okta handles auth automatically via the ingress gateway —
  do NOT implement login, OAuth, or session management
- The gateway injects a trusted **`X-Userinfo`** header (base64 JSON)
  with claims: `sub`, `email`, `name`, `given_name`, `family_name`, `groups`
- The `groups` claim is an array of Okta group names the user belongs to.
  It requires `groups` in the OIDC scope — verify it is present, and add it if missing.
- **Default access**: all authenticated Phrase users can access the app — no group checks needed
- **Optional RBAC**: to restrict access or assign roles based on group membership,
  decode `X-Userinfo`, read the `groups` array, and match against your app's expected groups.
  The platform does not prescribe group names — coordinate with your Okta admin to create
  groups and assign users. Your app decides what each group means.
