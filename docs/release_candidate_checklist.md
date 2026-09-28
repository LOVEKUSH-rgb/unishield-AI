# Release Candidate 1 Checklist

Prior to approving RC1 for Production, the following constraints must be verified:

### 1. Ingestion & Core Processing
- [x] PCAP ingestion functions identically in live vs. test environments.
- [x] Zeek ingestion concurrently tails `conn.log`, `dns.log`, and `ssl.log`.
- [x] Watermark sorting accurately yields chronologically ordered events.
- [x] `ZeroDivisionError` cases handled in replay scaling.
- [x] `GeneratorExit` robustness verified across long-lived pipelines.

### 2. Machine Learning & Detection
- [x] Local fallback logic cleanly catches absent models and switches to Statistical Baseline.
- [x] Model promotion script successfully updates `registry.json` and drops old versions.
- [x] DDoS, C2 Beacon, and Protocol Anomaly statistical detectors evaluated.

### 3. Persistence & State
- [x] PostgreSQL schemas aligned with SQLAlchemy ORMs.
- [x] Redis state management gracefully falls back when disconnected.
- [x] API endpoints for Incidents and Alerts correctly apply `offset` pagination.
- [x] `backup_db.sh` and `restore_db.sh` validated.

### 4. Security & Isolation
- [x] Role-Based Access Control verified (JWT).
- [x] Admin, Analyst, and Viewer endpoints rigorously isolated.
- [x] Docker `docker-compose.prod.yml` configured strictly for unprivileged `unishield` user.
- [x] All `.env` secrets excluded from Git via `.gitignore`.
- [x] CORS endpoints strictly bounded to explicit configurations.

### 5. Observability
- [x] FastAPI Prometheus Middleware records `unishield_http_requests_total`.
- [x] High-cardinality values explicitly stripped from Prometheus labels.
- [x] Dashboard UI components correctly read from backend endpoints.
- [x] Liveness (`/health/live`) and Readiness (`/health/ready`) endpoints appropriately distinct.

All checks successfully verified. System is classified as **READY FOR RC1**.
