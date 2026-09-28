# Changelog

All notable changes to the UniShield AI SOC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc.1] - 2026-08-29
### Added
- Real-time concurrent Zeek ingestion (conn, dns, ssl) with timestamp-aware watermark merging.
- Complete ML model lifecycle registry (promotion, rollback, validation).
- FastAPI backend serving Replay Controls, Dashboard Data, and Prometheus Metrics.
- Role-Based Access Control (RBAC) via JWTs (admin, analyst, viewer).
- Graceful statistical fallback in the feature pipeline if ML models are unavailable.
- Deep pagination across Incident and Alert REST API endpoints.
- Docker compose environment (Production and Testing variants).
- `restore_db.sh` logical backup restoration script.

### Fixed
- Out-of-order Zeek event flushing causing dropped packets during stream closures.
- Over-counting and memory leaks in the active FlowManager during long replays.
- Broad exception capturing masking internal application errors in StateManager.
- GeneratorExit `RuntimeError` during concurrent tailing tests.

### Changed
- Refactored PostgreSQL models and decoupled schema creation to Alembic migrations.
- Extracted observability metrics out of core logic into `prometheus_metrics.py`.

### Security
- Secrets decoupled from `.env.example`.
- Configured PostgreSQL and Redis to enforce explicit authentication.
- All Docker containers dropped to unprivileged `unishield` user (UID 999).
- Hardened FastAPI by adding precise CORS origins.
