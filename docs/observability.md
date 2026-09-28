# UniShield Observability & Monitoring

This document details the telemetry and alerting infrastructure for the UniShield AI SOC.

## 1. Architecture
The monitoring stack runs alongside UniShield in the same Docker Compose network:
- **Prometheus** (`unishield-prometheus:9090`): Internal metrics scraper. Pulls data from UniShield API `/metrics` every 15s.
- **Grafana** (`unishield-grafana:3000`): External dashboard visualization. Connects internally to Prometheus.

## 2. Health Endpoints (API)
- `/health/live`: Basic TCP/HTTP responsiveness test. Does not check dependencies.
- `/health/ready`: Deep health check. Ensures PostgreSQL, Redis, and ML Models are healthy and ready to accept traffic.
- `/metrics`: Standard Prometheus metrics exposition endpoint.

## 3. Key Metrics
- `unishield_ingestion_events_total`: Total events ingested.
- `unishield_ingestion_queue_depth`: Current depth of background Zeek processing queue.
- `unishield_pipeline_latency_seconds`: Feature extraction and flow aggregation latency (Histogram).
- `unishield_detector_invocations_total`: Invocations per detector.
- `unishield_database_operations_total`: Tracks SQL queries latency and counts.

## 4. Alerting Rules
- **UniShieldAPIDown** (CRITICAL): Prometheus cannot reach the `/metrics` endpoint for >1m.
- **IngestionQueueSaturated** (WARNING): Queue depth >50,000. Indicates API thread falling behind ingestion.
- **HighPipelineLatency** (WARNING): P95 pipeline latency >500ms.
- **DatabaseErrorsDetected** (WARNING): Database error rate >5% over 1m.

## 5. Security & Isolation
- Prometheus is not bound to a host port by default; it is accessed purely by Grafana on the internal `unishield-backend` network.
- High cardinality labels (e.g. UUIDs, IPs) are strictly avoided in Prometheus metrics to prevent memory saturation. Use JSON structural logging for trace-level diagnostics (via `correlation_id`).
