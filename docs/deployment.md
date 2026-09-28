# UniShield AI Deployment Guide

## 1. Requirements
- Docker and Docker Compose
- PostgreSQL client tools (`pg_dump`) for backup scripts
- Python 3.12 (for local development)

## 2. Environments Overview
UniShield strictly differentiates environments via the `ENVIRONMENT` variable:
- **`development`**: Reload mode enabled, database ports exposed to host. Uses `docker-compose.dev.yml`.
- **`test`**: Uses ephemeral in-memory/tmpfs databases. Used by CI/CD via `docker-compose.test.yml`.
- **`production`**: Strict isolation, missing config safety checks, resource limits, restart policies. Uses `docker-compose.prod.yml`.

## 3. Secret Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Generate a strong JWT key and assign secure database credentials:
```bash
openssl rand -hex 32
```
Update `JWT_SECRET_KEY`, `POSTGRES_PASSWORD`, and `REDIS_PASSWORD` in `.env`.

## 4. Production Deployment
To deploy to production:
```bash
bash scripts/deploy.sh
```
This script validates `.env`, builds the images, starts infrastructure, and waits for health checks.
Alternatively manually:
```bash
docker compose -f docker-compose.prod.yml up -d --build
```

## 5. Database Migrations
Migrations are handled automatically by `scripts/entrypoint.sh` for development and production modes. It runs `alembic upgrade head`.

## 6. Health Checks
Health checks are implemented natively in Docker Compose for Postgres and Redis.
The API has a `/health` endpoint checked during `deploy.sh`. The dashboard has `/_stcore/health`.

## 7. Troubleshooting
If containers fail to start, view logs:
```bash
docker compose -f docker-compose.prod.yml logs -f
```
If the API fails quickly, verify that `.env` has all required secrets (especially `JWT_SECRET_KEY`).

## 8. Backups
Run `bash scripts/backup_db.sh` to generate a logical `pg_dump` of the PostgreSQL database to the `./backups` folder.

## 9. Restore
To restore:
```bash
cat backups/unishield_db_DATE.sql | docker exec -i unishield-postgres psql -U unishield_user -d unishield
```
(Replace with your username/DB from `.env`).
