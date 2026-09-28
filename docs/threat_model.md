# UniShield AI Threat Model

## Overview
UniShield AI is designed as a **passive network monitoring and detection system**. It does not sit inline and does not drop packets. Its primary function is to ingest mirrored PCAP or Zeek telemetry, run statistical and ML models, and present insights via a SOC dashboard.

Because it is a passive system, the threat model focuses heavily on:
- Unauthorized access to telemetry and incident data.
- System availability (e.g., DoS on ingestion).
- Maliciously crafted telemetry (e.g., evasion or ingestion exploits).
- Container escape and lateral movement.

## Trust Boundaries
1. **Host Network ↔ Frontend Network:** End users (Analysts) access the Streamlit Dashboard and FastAPI backend via HTTP(s).
2. **Frontend Network ↔ Backend Network:** The FastAPI backend queries PostgreSQL and Redis.
3. **Ingestion ↔ Backend Network:** Zeek and the Replay Manager ingest external files and network streams.

## Threat Assessment

### 1. Spoofing (Authentication & Identity)
- **Threat:** An attacker attempts to access the dashboard or API without credentials.
- **Mitigation:** JWT-based OAuth2 Password Bearer authentication is enforced on all API endpoints and the dashboard. The secret key is injected via environment variables (`JWT_SECRET_KEY`).

### 2. Tampering (Data Integrity)
- **Threat:** An attacker modifies database records, ML models, or alert thresholds.
- **Mitigation:** 
  - PostgreSQL and Redis are isolated within an internal Docker network (`unishield-backend`) and require strong passwords.
  - Role-Based Access Control (RBAC) ensures only `admin` users can load PCAPs, load models, or change configuration. `viewer` users have read-only access.

### 3. Repudiation
- **Threat:** An action (e.g., ignoring an alert) cannot be traced to a specific analyst.
- **Mitigation:** The JWT token contains the user's identity, allowing future phases to implement comprehensive audit logging for all state-changing API requests.

### 4. Information Disclosure
- **Threat:** Sensitive network telemetry or configuration secrets are leaked.
- **Mitigation:**
  - Hardcoded credentials have been completely removed in favor of `.env` injection.
  - The API explicitly restricts CORS to configured origins, preventing Cross-Site Request Forgery (CSRF) based data theft.
  - Path traversal protections (`validate_safe_path`) prevent arbitrary file reads through the PCAP/Zeek loaders.

### 5. Denial of Service
- **Threat:** High-volume traffic or large PCAPs crash the application.
- **Mitigation:** 
  - Ingestion queues (Phase 21) are bounded.
  - Container resource limits can be enforced via Docker Compose.

### 6. Elevation of Privilege
- **Threat:** An attacker exploits a vulnerability in the API or Zeek to gain root access to the host.
- **Mitigation:** Containers run as non-root users (`unishield:unishield`). The Docker daemon provides namespace isolation.

## Residual Risks
- The current ingestion engine (Zeek) processes untrusted data. If a zero-day vulnerability exists in Zeek's protocol parsers, it could lead to container compromise. The primary mitigation is strict container network isolation and minimal privileges.
