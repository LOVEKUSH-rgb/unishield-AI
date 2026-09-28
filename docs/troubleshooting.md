# Troubleshooting UniShield Observability

## 1. Dashboard Shows No Data
- **Cause**: Prometheus container failed or API is down.
- **Resolution**:
  - Run `docker logs unishield-prometheus`
  - Ensure `/health/live` returns HTTP 200 on `localhost:8000`.

## 2. IngestionQueueSaturated Alert Firing
- **Cause**: Heavy traffic volume (Zeek) overwhelming the background ingestion pipeline.
- **Resolution**: 
  - The pipeline has backpressure enabled. If depth >100,000 it will naturally drop events.
  - Scale up resources for the UniShield container or reduce Zeek log verbosity.

## 3. DatabaseErrorsDetected Alert Firing
- **Cause**: PostgreSQL connection failure or locking issues.
- **Resolution**:
  - Verify `postgres` container logs.
  - Validate credentials in `.env` (`POSTGRES_USER`, `POSTGRES_PASSWORD`).
  - Run `alembic upgrade head` if schema issues are suspected.

## 4. Grafana Cannot Connect to Prometheus
- **Cause**: Docker network isolation broken or wrong URL in Datasource.
- **Resolution**:
  - Grafana is provisioned to use `http://prometheus:9090`. Ensure both containers are on the `unishield-backend` docker network.
  - Test via `docker exec -it unishield-grafana curl http://prometheus:9090/-/healthy`.
