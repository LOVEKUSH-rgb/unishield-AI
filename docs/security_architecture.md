# UniShield AI Security Architecture

This document describes the security controls implemented in Phase 23 to harden the UniShield AI deployment.

## 1. Network Architecture (Docker Isolation)

UniShield uses a two-tier network architecture to isolate sensitive components:

- **`unishield-frontend`**: A bridge network connecting the Streamlit Dashboard and the FastAPI backend. Only ports `8000` (API) and `8501` (Dashboard) are exposed to the host.
- **`unishield-backend`**: A strictly internal bridge network. The FastAPI backend, PostgreSQL database, Redis store, and Zeek ingestion container reside here. 
  - **No Host Exposure:** PostgreSQL (`5432`) and Redis (`6379`) are NOT published to the host, completely eliminating external direct-access vectors.

## 2. Authentication and Authorization

- **JWT Auth:** The API uses OAuth2 with Password Bearer to issue JSON Web Tokens (JWT). The Streamlit dashboard stores this token and passes it in the `Authorization` header for all requests.
- **Role-Based Access Control (RBAC):**
  - `viewer`: Can read metrics, incidents, and alerts.
  - `analyst`: Can acknowledge/resolve incidents (planned for future phases).
  - `admin`: Can execute sensitive replay and ingestion controls (`/replay/*`, `/ingest/*`).
- **Default Seeding:** Upon the first launch, the database seeds `admin`, `analyst`, and `viewer` accounts with hashed default passwords.

## 3. Configuration and Secrets Management

- **No Hardcoded Secrets:** Previous implementations of `os.environ.get()` with hardcoded fallback credentials were removed.
- **Pydantic Settings:** Configuration is now managed centrally via `src/utils/config.py` using `pydantic-settings`. The application expects an `.env` file and will crash on startup if critical secrets (like `JWT_SECRET_KEY`) are missing in production.

## 4. Container Hardening

- **Non-Root Execution:** Both the `unishield-api` and `unishield-dashboard` containers now explicitly create and use a non-root `unishield` user, limiting the blast radius of any remote code execution vulnerabilities in Python dependencies.
- **Minimal Base Images:** Alpine/Slim images are used to reduce the attack surface.

## 5. Input Validation

- **Path Traversal Protection:** The replay and ingestion endpoints (`/replay/load` and `/ingest/zeek`) strictly validate that requested files reside within the authorized `data/` directory using Python's `Path.resolve().is_relative_to()`.
