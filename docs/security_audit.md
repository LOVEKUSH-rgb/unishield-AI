# UniShield AI -- Phase 23 Security Audit Report

## 1. Network & Port Exposure
- **PostgreSQL**: Hard-bound to host port `5432:5432` in `docker-compose.yml`, making it publicly exposed on the host.
- **Redis**: Hard-bound to host port `6379:6379` in `docker-compose.yml`, making it publicly exposed on the host.
- **Docker Networks**: No explicit, segmented custom networks (e.g., `frontend`, `api_network`) are defined in `docker-compose.yml`, placing everything in the default bridge network with exposed ports.

## 2. Hardcoded Credentials & Secrets
- **PostgreSQL**: `docker-compose.yml` explicitly defines `POSTGRES_USER=unishield` and `POSTGRES_PASSWORD=unishield`.
- **Database Connection String**: `docker-compose.yml` sets `DATABASE_URL=postgresql://unishield:unishield@postgres:5432/unishield`. `src/persistence/database.py` falls back to `sqlite:///./data/unishield.db` but relies directly on `os.environ.get("DATABASE_URL")`.
- **Redis Connection String**: `src/persistence/redis_client.py` uses `redis://localhost:6379/0` fallback with no authentication built-in.

## 3. Missing Authentication & Authorization
- **FastAPI**: Endpoints (including `/health`, `/metrics`, `/replay/*`, `/ingest/*`) are entirely open. There is no JWT middleware, no login endpoint, and no Role-Based Access Control (RBAC).
- **Streamlit Dashboard**: Lacks an authentication flow. Connects directly to the API without bearer tokens.
- **Redis Auth**: Redis instance starts without the `--requirepass` flag.

## 4. Insecure Configuration & Overly Permissive Defaults
- **CORS**: `src/api/app.py` sets `allow_origins=["*"]`, permitting any external site to interact with the API.
- **Configuration Management**: `.env` and `.env.example` do not exist. Configuration relies on loosely scattered `os.environ.get()` calls and a `config.yaml` with an empty `password: ""` field that is not populated correctly.
- **Container Privileges**: The `Dockerfile` runs as root by default (no `USER` directive). 
- **Missing Files**: `docker/Dockerfile.dashboard` referenced in `docker-compose.yml` does not exist, causing deployment failures and masking potential container misconfigurations.

## 5. File & Input Validation
- Endpoints like `/replay/load` accept arbitrary file paths (`req.pcap_path`) and `/ingest/zeek` accepts `req.zeek_dir`. Currently, these paths are not validated against a safe directory boundary, posing a Path Traversal risk.

## 6. Logs & Auditing
- System has no structured security audit logs for actions like "Stop Replay", "Load PCAP", or "Failed Login" (since logins do not exist).

This audit identifies severe production risks. The proposed architecture in Phase 23 will systematically mitigate these vulnerabilities.
