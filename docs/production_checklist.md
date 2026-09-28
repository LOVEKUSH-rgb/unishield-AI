# UniShield AI Production Readiness Checklist

## Infrastructure
- [x] Docker images build reproducibly
- [x] Application containers run as non-root (`unishield`)
- [x] PostgreSQL is isolated to `unishield-backend` network
- [x] Redis is isolated to `unishield-backend` network
- [x] Zeek volume mounts and permissions are minimal
- [x] Persistent volumes are configured for Postgres (`pgdata`)
- [x] Health checks are properly defined and used for dependencies

## Security
- [x] Secrets are externalized (managed via `.env`)
- [x] `.dockerignore` prevents `.env` and `.git` from entering images
- [x] JWT is correctly configured and enforced
- [x] Authentication is mandatory
- [x] RBAC is functional
- [x] CORS is restricted via `CORS_ALLOWED_ORIGINS`
- [x] No hardcoded credentials exist in code
- [x] Log configurations do not leak secrets

## Application
- [x] FastAPI `/health` endpoint responds correctly
- [x] Streamlit dashboard successfully communicates with API
- [x] Startup scripts cleanly retry Postgres and Redis connections
- [x] ML Registry falls back gracefully to statistical detection if ML models are absent

## Testing & CI
- [x] Pytest suite fully passes
- [x] Security suite passes
- [x] GitHub Actions CI pipeline is configured (`ci.yml`)
- [x] Docker smoke tests execute within CI
- [x] PCAP & Zeek end-to-end telemetry verified
- [x] Authenticated UI end-to-end verified

## Operations
- [x] Backup script `backup_db.sh` is available and documented
- [x] Restore process is documented
- [x] Rollback strategies (Image, Database, Redis) are documented
- [x] Deployment via `deploy.sh` is fully documented
