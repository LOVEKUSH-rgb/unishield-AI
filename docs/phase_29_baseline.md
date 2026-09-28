# Phase 29 — Repository Baseline Audit

## 1. Repository State
- **Root Files**: 17 (including README.md, docker-compose files, requirements.txt, alembic.ini, and configurations)
- **Directories**: 16 (`src`, `tests`, `docs`, `config`, `dashboard`, `docker`, `models`, `monitoring`, `migrations`, etc.)
- **Overall Architecture**: Strictly passive SOC architecture consisting of an ingestion pipeline (PCAP and Zeek), feature extraction, detection engine (6 detectors with ML and statistical fallback), correlation/risk engine, API, and Dashboard. 

## 2. Current Docker Topology
The architecture relies on 7 specialized Docker containers:
1. `unishield-api`: FastAPI backend and central pipeline orchestrator
2. `postgres`: Persistent storage for Incidents and Alerts
3. `redis`: Ephemeral state manager for pub/sub, caching, and cross-thread communication
4. `unishield-dashboard`: Streamlit frontend for the SOC analysts
5. `zeek`: Network security monitor producing concurrent JSON logs
6. `prometheus`: Scrapes metrics from `unishield-api`
7. `grafana`: Visualizes Prometheus observability metrics

## 3. Current Test Count
- **Total Tests**: 482
- **Passed**: 479
- **Skipped**: 3
- **Failed**: 0
- **Duration**: ~62 seconds
- **Health**: Perfect pass rate. No unexpected failures.

## 4. Current Model Artifacts
Two ML models are actively deployed in the registry under `models/trained/`:
1. `dga_random_forest/v1.0.0/`
   - Artifact: `dga_random_forest.pkl`
   - Manifest: `manifest.json`
2. `encrypted_xgboost/v1.0.0/`
   - Artifact: `encrypted_xgboost.json`
   - Manifest: `manifest.json`

## 5. Current Ingestion Modes
1. **PCAP**: Processed via `PcapReader` utilizing `dpkt` for raw packet dissection.
2. **Zeek**: Processed via `ZeekLogReader` which concurrently tails `conn.log`, `dns.log`, and `ssl.log` applying timestamp-aware watermark merging.

## 6. Current Authentication Model
- **Backend API**: OAuth2 Password Flow with JWT Bearer tokens (Signed using `HS256`, 60 min expiration). Role-Based Access Control (RBAC) supports Viewer, Analyst, and Admin roles.
- **Frontend Dashboard**: Native Streamlit session-based auth that securely injects the API's JWT into backend requests.

## 7. Current Persistence Model
- **Alerts/Incidents**: Stored persistently in PostgreSQL (`AlertModel`, `IncidentModel`, `IncidentAlertModel`, `EvidenceModel`).
- **Telemetry State/Metrics**: Stored ephemerally in Redis (`StateManager` and `FeaturePipeline`).
- **Models**: Stored locally in the filesystem (`model_registry_path`) with in-memory fallback.

## 8. Known Limitations
- Ground truth labels are unavailable in a passive SOC environment. Accuracy metrics cannot be definitively measured dynamically without external validation.
- Long-duration stability tests (soak tests) may be heavily constrained by the localized test environment resources.
